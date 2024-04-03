#!/bin/bash

read -p "请输入执行次数: " count

# 检查输入是否为正整数
re='^[0-9]+$'
if ! [[ $count =~ $re ]] || [ $count -lt 1 ]; then
  echo "请输入一个大于等于 1 的正整数。"
  exit 1
fi

# 生成随机数
random_number=$((RANDOM % (100000 + 1) + 1))

# 循环执行 cmc 命令
for ((i = 1; i <= count; i++)); do
  ./cmc client contract user invoke \
--contract-name=fact \
--method=save \
--sdk-conf-path=./testdata/sdk_config.yml \
--params="{\"file_name\":\"fzuscriptgeneralfzuscriptgeneralfzuscriptgeneralfzuscriptgeneralfzuscriptgeneralfzuscriptgeneralfzuscriptgeneralfzuscriptgeneralfzuscriptgeneral$random_number$i\",\"file_hash\":\"fzuscriptgeneralfzuscriptgeneralfzuscriptgeneralfzuscriptgeneralfzuscriptgeneralfzuscriptgeneralfzuscriptgeneralfzuscriptgeneral$random_number$i\",\"time\":\"6543234\"}" \
--sync-result=true
  sleep 0.2  # 添加 1 秒的延迟
done
