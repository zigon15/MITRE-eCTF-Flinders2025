docker build -t decoder ./decoder
docker run --rm -v ./decoder:/decoder -v ./global.secrets:/global.secrets:ro -v ./deadbeef_build:/out -e DECODER_ID=0xdeadbeef decoder