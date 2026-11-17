// =============================================================================
// Менеджер правил ИАС БИ — Java
// Компиляция: javac RuleManager.java
// Запуск:     java RuleManager                       (показать все правила)
//             java RuleManager add "Открытый RDP" unauthorized_access 8.5 port eq 3389 "Закрыть порт 3389"
//             java RuleManager category unauthorized_access
// Читает rules.yaml и файлы из папки rules/, новые правила сохраняет в rules/ (их подхватывает Python-движок).
// =============================================================================
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.LocalDate;
import java.util.*;
import java.util.stream.Collectors;

public class RuleManager {
    private final Path baseDir;
    private final Path rulesDir;
    private final List<Rule> rules = new ArrayList<>();

    public static class Rule {
        public String name, category, field = "", operator = "", value = "", source = "rules.yaml";
        public double riskScore;
        public List<String> recommendations = new ArrayList<>();

        @Override
        public String toString() {
            return String.format("[%s] %s (риск %.1f) если %s %s %s  <%s>",
                    category, name, riskScore, field, operator, value, source);
        }
    }

    public RuleManager(String baseDir) {
        this.baseDir = Paths.get(baseDir);
        this.rulesDir = this.baseDir.resolve("rules");
    }

    /** Загрузка правил из rules.yaml и rules/*.yaml */
    public void loadRules() throws IOException {
        Files.createDirectories(rulesDir);
        rules.clear();
        Path main = baseDir.resolve("rules.yaml");
        if (Files.exists(main)) parseRuleFile(main);
        try (var stream = Files.list(rulesDir)) {
            for (Path p : stream.filter(x -> x.toString().endsWith(".yaml")).sorted().collect(Collectors.toList()))
                parseRuleFile(p);
        }
        System.out.println("Загружено правил: " + rules.size());
    }

    private static String unq(String s) { return s.trim().replace("\"", ""); }

    /** Упрощённый разбор YAML нужного нам вида (без внешних библиотек) */
    private void parseRuleFile(Path file) throws IOException {
        Rule cur = null;
        boolean inRecs = false, firstCond = true;
        for (String raw : Files.readAllLines(file, StandardCharsets.UTF_8)) {
            String line = raw.trim();
            if (line.startsWith("- name:")) {
                if (cur != null) rules.add(cur);
                cur = new Rule();
                cur.source = file.getFileName().toString();
                cur.name = unq(line.substring(7));
                inRecs = false; firstCond = true;
            } else if (cur == null) {
                continue;
            } else if (line.startsWith("category:")) {
                cur.category = unq(line.substring(9));
            } else if (line.startsWith("risk_score:")) {
                cur.riskScore = Double.parseDouble(line.substring(11).trim());
            } else if (line.startsWith("recommendations:")) {
                inRecs = true;
            } else if (line.startsWith("conditions:")) {
                inRecs = false;
            } else if (line.startsWith("- field:") || line.startsWith("field:")) {
                if (firstCond) { cur.field = unq(line.substring(line.indexOf(':') + 1)); }
            } else if (line.startsWith("operator:")) {
                if (firstCond) cur.operator = unq(line.substring(9));
            } else if (line.startsWith("value:")) {
                if (firstCond) { cur.value = unq(line.substring(6)); firstCond = false; }
            } else if (inRecs && line.startsWith("- ")) {
                cur.recommendations.add(unq(line.substring(2)));
            }
        }
        if (cur != null) rules.add(cur);
    }

    /** Добавление нового правила: сохраняется отдельным файлом в rules/ */
    public Path addRule(Rule r) throws IOException {
        String file = r.name.replaceAll("[^\\p{L}\\p{Nd}]+", "_").toLowerCase() + ".yaml";
        Path path = rulesDir.resolve(file);
        boolean numeric = r.value.matches("\\d+(\\.\\d+)?");
        StringBuilder sb = new StringBuilder();
        sb.append("# создано RuleManager ").append(LocalDate.now()).append(", версия правила 1\n");
        sb.append("- name: \"").append(r.name).append("\"\n");
        sb.append("  category: \"").append(r.category).append("\"\n");
        sb.append("  risk_score: ").append(r.riskScore).append("\n");
        sb.append("  conditions:\n");
        sb.append("    - field: \"").append(r.field).append("\"\n");
        sb.append("      operator: \"").append(r.operator).append("\"\n");
        sb.append("      value: ").append(numeric ? r.value : "\"" + r.value + "\"").append("\n");
        sb.append("  recommendations:\n");
        for (String rec : r.recommendations) sb.append("    - \"").append(rec).append("\"\n");
        Files.write(path, sb.toString().getBytes(StandardCharsets.UTF_8));
        r.source = file;
        rules.add(r);
        System.out.println("Добавлено правило: " + r + "\nСохранено в " + path.getFileName());
        return path;
    }

    public void listRules() {
        System.out.println("\n=== Все правила ===");
        rules.forEach(System.out::println);
    }

    public List<Rule> findByCategory(String category) {
        return rules.stream().filter(r -> category.equals(r.category)).collect(Collectors.toList());
    }

    public static void main(String[] args) throws IOException {
        RuleManager m = new RuleManager(".");
        m.loadRules();
        if (args.length >= 1 && args[0].equals("add") && args.length >= 8) {
            Rule r = new Rule();
            r.name = args[1]; r.category = args[2]; r.riskScore = Double.parseDouble(args[3]);
            r.field = args[4]; r.operator = args[5]; r.value = args[6];
            r.recommendations.addAll(Arrays.asList(args).subList(7, args.length));
            m.addRule(r);
        } else if (args.length >= 2 && args[0].equals("category")) {
            System.out.println("\n=== Правила категории '" + args[1] + "' ===");
            m.findByCategory(args[1]).forEach(System.out::println);
            return;
        }
        m.listRules();
    }
}
