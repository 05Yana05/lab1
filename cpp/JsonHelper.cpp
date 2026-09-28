#include "JsonHelper.h"
#include <sstream>

using namespace std;

string JsonHelper::extractString(const string& json, const string& key) {
    // »щем "key":" в JSON
    string pattern = "\"" + key + "\":\"";
    size_t start = json.find(pattern);
    if (start == string::npos) {
        return "";
    }
    start += pattern.length();

    // »щем закрывающую кавычку
    size_t end = json.find('"', start);
    if (end == string::npos) {
        return "";
    }

    return json.substr(start, end - start);
}

string JsonHelper::escape(const string& value) {
    string result;
    result.reserve(value.size());
    for (char c : value) {
        if (c == '"')       result += "\\\"";
        else if (c == '\\') result += "\\\\";
        else if (c == '\n') result += "\\n";
        else if (c == '\r') result += "\\r";
        else if (c == '\t') result += "\\t";
        else                result += c;
    }
    return result;
}

string JsonHelper::buildJson(const initializer_list<pair<string, string>>& pairs) {
    stringstream ss;
    ss << "{";
    bool first = true;
    for (const auto& p : pairs) {
        if (!first) ss << ",";
        first = false;
        ss << "\"" << p.first << "\":\"" << escape(p.second) << "\"";
    }
    ss << "}";
    return ss.str();
}