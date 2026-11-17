// =============================================================================
// Парсер Nmap XML — быстрый разбор на C++ (libxml2)
// Компиляция: g++ -O2 -std=c++17 -o nmap_parser nmap_parser.cpp -lxml2 $(xml2-config --cflags)
// Запуск:     ./nmap_parser nmap_output.xml > nmap_parsed.json
// =============================================================================
#include <iostream>
#include <string>
#include <vector>
#include <libxml/parser.h>
#include <libxml/tree.h>

struct Port {
    int portid = 0;
    std::string protocol, state, service, version;
};
struct Host {
    std::string address, hostname;
    std::vector<Port> ports;
};

// значение атрибута или пустая строка
static std::string attr(xmlNode* node, const char* name) {
    xmlChar* v = xmlGetProp(node, (const xmlChar*)name);
    std::string s = v ? (const char*)v : "";
    if (v) xmlFree(v);
    return s;
}

// экранирование строки для JSON
static std::string esc(const std::string& in) {
    std::string out;
    for (char c : in) {
        if (c == '"' || c == '\\') { out += '\\'; out += c; }
        else if (c == '\n') out += "\\n";
        else if ((unsigned char)c < 0x20) out += ' ';
        else out += c;
    }
    return out;
}

// Рекурсивный обход XML-дерева внутри одного <host>
void parseHost(xmlNode* node, Host& host) {
    for (xmlNode* cur = node; cur; cur = cur->next) {
        if (cur->type != XML_ELEMENT_NODE) continue;
        std::string name = (const char*)cur->name;
        if (name == "address") {
            if (attr(cur, "addrtype") != "mac") host.address = attr(cur, "addr");
        } else if (name == "hostname") {
            host.hostname = attr(cur, "name");
        } else if (name == "port") {
            Port p;
            p.portid = std::stoi(attr(cur, "portid"));
            p.protocol = attr(cur, "protocol");
            for (xmlNode* child = cur->children; child; child = child->next) {
                if (child->type != XML_ELEMENT_NODE) continue;
                std::string cname = (const char*)child->name;
                if (cname == "state") p.state = attr(child, "state");
                else if (cname == "service") {
                    p.service = attr(child, "name");
                    // product + version: «OpenSSH 9.2p1 Debian ...»
                    std::string prod = attr(child, "product"), ver = attr(child, "version");
                    p.version = prod + (prod.empty() || ver.empty() ? "" : " ") + ver;
                }
            }
            host.ports.push_back(p);
            continue;               // внутрь <port> повторно не заходим
        }
        parseHost(cur->children, host);
    }
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <nmap_output.xml>" << std::endl;
        return 1;
    }
    xmlDoc* doc = xmlReadFile(argv[1], NULL, 0);
    if (!doc) {
        std::cerr << "Ошибка: не удалось открыть файл " << argv[1] << std::endl;
        return 1;
    }
    xmlNode* root = xmlDocGetRootElement(doc);
    std::vector<Host> hosts;
    for (xmlNode* cur = root->children; cur; cur = cur->next) {
        if (cur->type == XML_ELEMENT_NODE && std::string((const char*)cur->name) == "host") {
            Host h;
            parseHost(cur->children, h);
            hosts.push_back(h);
        }
    }
    // Вывод в JSON
    std::cout << "{\"hosts\": [" << std::endl;
    for (size_t i = 0; i < hosts.size(); ++i) {
        std::cout << " {\"address\": \"" << esc(hosts[i].address) << "\", ";
        std::cout << "\"hostname\": \"" << esc(hosts[i].hostname) << "\", \"ports\": [" << std::endl;
        for (size_t j = 0; j < hosts[i].ports.size(); ++j) {
            auto& p = hosts[i].ports[j];
            std::cout << "  {\"port\": " << p.portid << ", \"protocol\": \"" << esc(p.protocol)
                      << "\", \"state\": \"" << esc(p.state) << "\", \"service\": \"" << esc(p.service)
                      << "\", \"version\": \"" << esc(p.version) << "\"}";
            if (j + 1 < hosts[i].ports.size()) std::cout << ",";
            std::cout << std::endl;
        }
        std::cout << " ]}" << (i + 1 < hosts.size() ? "," : "") << std::endl;
    }
    std::cout << "]}" << std::endl;
    xmlFreeDoc(doc);
    xmlCleanupParser();
    return 0;
}
