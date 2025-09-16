Return-Path: <kasan-dev+bncBCCMH5WKTMGRBB6TUXDAMGQEGXOWZUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3a.google.com (mail-oa1-x3a.google.com [IPv6:2001:4860:4864:20::3a])
	by mail.lfdr.de (Postfix) with ESMTPS id DC53EB597F9
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Sep 2025 15:43:37 +0200 (CEST)
Received: by mail-oa1-x3a.google.com with SMTP id 586e51a60fabf-30ccec20b9bsf6015515fac.2
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Sep 2025 06:43:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758030216; cv=pass;
        d=google.com; s=arc-20240605;
        b=dEGN8aC8mexAvHUI4rwaw8P/YJePalPDNrHWlNVLPJavWko9UI/WcAG/sNGN9hhLQN
         otaglmowD1nIHyU5xdW/VxbL1NGexZ+JBk47m53zf/RVF7pdI3xkM13kl/ekfNY+jkn7
         WO2IeGnb5rw2BSQ4+OcegWlWiHpPn3vXNOdzOqSLrfroI69S5CTVXICNtJ1Q7rWIukaf
         bvXSta1eBUJ3KKkFo0mUDqy160QYYYEJz9GkaTZRqF8E7fWMIYS1lGm2VB/A77w124O/
         Sxen7f7IU/9+8KVwU276I5ohu/473grvv5twOxFfk0ErRjJ2BC6RmypIrmAkSY2JeTJ9
         zOjg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=wwPzUTNr8ePqzaL0MADk1gOZ4jCRFwEkkEWhKNYcanM=;
        fh=vaUJzf3BfGqRrqvg+Ob8vYH7Gl2web0Qbqg+7Hx4TEM=;
        b=ZX4WFrk4Cb33bvd439ripWy5Jv8R5NjdHoGUhVwuCwafdGvO7gZQhUeX1IFZ45PB6B
         NuyFm51vKz3QnZdVtoovl4mLTmKMB4AVHJ6MB1ry29LwNX6c1WIJsg4bzU7Qrcnq/3My
         H21xVk0wDTu4D4Hwysj0vmT6lf3JbFb5W4jY/0esKt2hBjSWOi0Ybu122ObYYneGc/QI
         OoSTGQ/ZX7zP3naO730GR+g5mSfUxK4oMH7ge7mYa4cvema/w88yHZQmz4lJ9wk0pGoM
         DrF2kxCF347o+1qbAyqkgyRuCiuNRywouOq+PpkgOXrrcG7DpZ3IFWkM89LVnYU/Ktoe
         h7Rg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=oCFqzuCg;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2d as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758030216; x=1758635016; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=wwPzUTNr8ePqzaL0MADk1gOZ4jCRFwEkkEWhKNYcanM=;
        b=LBXh6kFdan4rMssTNWQk3AnVIZmlRJUH3C4XHfKIcTSrfrUf9vJ4eoPPu5WDuqYako
         4Hbq0Hw+vPvN7oQLfgHYlAMspJC41scEKnqfxkHFev2I4JjwDOg8OjOk5NRRKEcOzSBS
         kJt/14a/16e768fnGTIAKR/2bSm5hmY+N8C94PDhubt2AWlTQjNgZSCWC9B3AYpfpzsH
         iqpDkBUOK5zqVx6LykS6aabje3OGRjY017VN3QdZQa8zEK8j+8fEx7fyfAbofFFYNdaR
         lp8HZ09dfCCE/3TDi4Pdo4NbEJkCHBQGbIYiaEs2VGleK1ZJPxE3c14nQBMk6yOIo/lE
         zmaQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758030216; x=1758635016;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=wwPzUTNr8ePqzaL0MADk1gOZ4jCRFwEkkEWhKNYcanM=;
        b=xHelRLtoujVRS4kT/ZWK3zrAR/q5YirghELO/Yf5A/6YYqalKl4MgCpf6S+9WHH2zh
         oACf+gCg6TIap5As5hL4jAYvCoTE+RnphwRhVspLWIEudCYfkmDtLCalxH3JrSF5qmpr
         +Df/te/gw0Y/mKkjcHYqFV/QeDx46ddjhnHlFz8YVYvHmAGYuG4IhLwV84YPDpa9Bp3u
         rnFXj2kV5tEdnACj3P2D4JLeQoVKEIzYwM0k+lACY5v0WOd4ebi7EJu1OLWv2+YkdxB7
         WZVhpoQ5/gbC20TS5nILdtkaZSBbZJP2VqME6v7zlMWQRwjziBuu9xs1wGiDb2RTlQEm
         njHw==
X-Forwarded-Encrypted: i=2; AJvYcCV0scDiDZ24kUGDLtvJ87mYZp9uZx1u5WMcFws9VFfzYusHoAI1TjNaV/UT+VkzmrA8zlDujw==@lfdr.de
X-Gm-Message-State: AOJu0Yykufq94WJgJixAmjq5Rv3F8dhWRu0syedqtO94ETRGg8pgdRQl
	9t60WmNH9gnQMB914Tg1hYFJorI2Viy8RHuo65AI4OOMFI7jyjKWVeez
X-Google-Smtp-Source: AGHT+IEsi/jelJN8fShRw9jHZHxVWcKMquR2CrfXoSA9dtihOTMWIxsHvgu8Emv8ElHcMXiFBOC56A==
X-Received: by 2002:a05:6870:8996:b0:30c:aa7:8fc1 with SMTP id 586e51a60fabf-32e560c2dd7mr9878415fac.26.1758030216439;
        Tue, 16 Sep 2025 06:43:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd5mSpd5Br4v5GmjenCMd5yBLUS9GbnLr3CAo0Nkoifo6Q==
Received: by 2002:a05:6870:f104:b0:31d:8e96:6f5e with SMTP id
 586e51a60fabf-32d06a348fbls3561062fac.2.-pod-prod-08-us; Tue, 16 Sep 2025
 06:43:34 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWmk/hJKII2rNpYQbeNycPghfKL2ldfMxmHR/Tdcr4RfTbi9xzgW2hDUud2Rmd8496VF+QIEGtZi50=@googlegroups.com
X-Received: by 2002:a05:6808:19a9:b0:438:40c3:8759 with SMTP id 5614622812f47-43b8d9fad7emr8961329b6e.30.1758030214392;
        Tue, 16 Sep 2025 06:43:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758030214; cv=none;
        d=google.com; s=arc-20240605;
        b=DT/UHHwXe52JLUeuuoruJWzYttECozPuiGOXZ91mcMjGH1SOTRWa9TIRLemwkiiusi
         9TS6XcdFJozoeempudtKAz52W0SmpbUfkNOGqJYcrtti88reWPxf7OgMxkEby+PSrheo
         q6tejQyTx2tE8LSDqFm6y84O5ZjtBGOARYVKViZUpScz3xE/9QK/ENXlESYWu+dPmeMJ
         oP8BxLC0djTbMBRZhEu42ucDhR0vIcMa9Xr6W16/zUmYi8GKk1U9QQxH0Lew7WU15ojg
         OTF/3cj/TrFlZf1C750VoB2qqoH0n9LWsjIiP+8gGbTdwqFBIaow0LiS+WrUy6ZhEjRZ
         nagw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=WFMguP23bZIISRu8P8L8i4YMMkZ2fq1VcnZsxEVckmk=;
        fh=4lVkgRos2cZKW5xvDONELsqCNhpf8brfn6j9DDDflp8=;
        b=NnaphGkWHEasFpdXUSdM/CIZrtAJ0CTT6Dwaf4ic0OF4N51Rh3Y1LIybgNriubz+Bu
         clvradOzl6JFdoc3iqAvSGKhujOpzVIpmWhWZLFcDBU8dV8z/stVFTj5Ul/BqD5BB50W
         W6W5yRXvjyKvPI/uTymfuTfX0cNOGIcc6Eki9A0CwzEKmOHof0fX9IwvXR+vVmPhGogl
         c5J/Z381hEDKgR4PZx5cbX1TFaHDfZU2Tci3sAYrOUzfUy9i89S0D5oztaUEXknZ1qH8
         tMnA5ZQVtKhWOnPRa8lPHd3G36TWAk1/vIhJJRHhFgOWSSsmOim8v8s7qDpj9M7+gzrc
         bXXQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=oCFqzuCg;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2d as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf2d.google.com (mail-qv1-xf2d.google.com. [2607:f8b0:4864:20::f2d])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-43b8dd4c1a0si441084b6e.5.2025.09.16.06.43.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 Sep 2025 06:43:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2d as permitted sender) client-ip=2607:f8b0:4864:20::f2d;
Received: by mail-qv1-xf2d.google.com with SMTP id 6a1803df08f44-77623a63dc5so16091886d6.0
        for <kasan-dev@googlegroups.com>; Tue, 16 Sep 2025 06:43:34 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUsPjjiu4MGbVPnMUj3WI9tqJaJEjoO7v7Yc5HLirlDxOtz9zodiUbPK4SU0+R9wvTpJS4Ktwrdraw=@googlegroups.com
X-Gm-Gg: ASbGncuqSe3Z2Z1Q9JED3fmmh5iNz3ylNj//BsYiYegs9U/D8r7r/oM0MzuSYYrmUEm
	rKDokdYpubHHtzRbv6Ygrbg4DI3b5K4BDyXzmCN11kguFqs2XjTkPIFe28yYoTB4Yy+fF6oIitm
	EgKtHqwUgDFi6bxUQuEXkJrEJVxe03URV5iVCMwKbvBB4S9Eo3SHXpI9WUMq6MHu1LA23YFZhdG
	BYzXJlWagtiI/bWtwLeJ15RWaGcHPIvnlB4vdxtYKJB
X-Received: by 2002:a05:6214:2624:b0:71c:53c0:5674 with SMTP id
 6a1803df08f44-767bb3b5cc7mr189377726d6.7.1758030212716; Tue, 16 Sep 2025
 06:43:32 -0700 (PDT)
MIME-Version: 1.0
References: <20250916090109.91132-1-ethan.w.s.graham@gmail.com> <20250916090109.91132-5-ethan.w.s.graham@gmail.com>
In-Reply-To: <20250916090109.91132-5-ethan.w.s.graham@gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 16 Sep 2025 15:42:55 +0200
X-Gm-Features: AS18NWDFPFWnjGnn0Ya31_ptvZRyrk4s5Sg6fkIlAJtVA6vYI3uU8Zv2xeIdCLw
Message-ID: <CAG_fn=UJsV1ibxSf6D+QU4ds1mHUG77NWJ5TR3sVs3f696RgiA@mail.gmail.com>
Subject: Re: [PATCH v1 04/10] tools: add kfuzztest-bridge utility
To: Ethan Graham <ethan.w.s.graham@gmail.com>
Cc: ethangraham@google.com, andreyknvl@gmail.com, andy@kernel.org, 
	brauner@kernel.org, brendan.higgins@linux.dev, davem@davemloft.net, 
	davidgow@google.com, dhowells@redhat.com, dvyukov@google.com, 
	elver@google.com, herbert@gondor.apana.org.au, ignat@cloudflare.com, 
	jack@suse.cz, jannh@google.com, johannes@sipsolutions.net, 
	kasan-dev@googlegroups.com, kees@kernel.org, kunit-dev@googlegroups.com, 
	linux-crypto@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, lukas@wunner.de, rmoar@google.com, shuah@kernel.org, 
	tarasmadan@google.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=oCFqzuCg;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2d as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

> ---
> v3:

Please change the version number to something like "RFC v3" (here and
in other patches)


> +
> +static int invoke_one(const char *input_fmt, const char *fuzz_target, const char *input_filepath)
> +{
> +       struct ast_node *ast_prog;
> +       struct byte_buffer *bb;
> +       struct rand_stream *rs;
> +       struct token **tokens;
> +       size_t num_tokens;
> +       size_t num_bytes;
> +       int err;
> +
> +       err = tokenize(input_fmt, &tokens, &num_tokens);
> +       if (err) {
> +               fprintf(stderr, "tokenization failed: %s\n", strerror(-err));
> +               return err;
> +       }

You should be freeing `tokens` somewhere.

> +
> +       err = parse(tokens, num_tokens, &ast_prog);
> +       if (err) {
> +               fprintf(stderr, "parsing failed: %s\n", strerror(-err));
> +               return err;
> +       }
> +
> +       rs = new_rand_stream(input_filepath, 1024);

You need to bail out here if `rs` is NULL, otherwise encode() will crash.

> +       err = encode(ast_prog, rs, &num_bytes, &bb);

`ast_prog` also needs to be freed at the end of this function.

> +int main(int argc, char *argv[])
> +{
> +       if (argc != 4) {
> +               printf("Usage: %s <input-description> <fuzz-target-name> <input-file>\n", argv[0]);
> +               printf("For more detailed information see /Documentation/dev-tools/kfuzztest.rst\n");

This should be Documentation/dev-tools/kfuzztest.rst without the leading slash.

> +static int read_minalign(struct encoder_ctx *ctx)
> +{
> +       const char *minalign_file = "/sys/kernel/debug/kfuzztest/_config/minalign";
> +       char buffer[64 + 1];
> +       int count = 0;
> +       int ret = 0;
> +
> +       FILE *f = fopen(minalign_file, "r");
> +       if (!f)
> +               return -ENOENT;
> +
> +       while (fread(&buffer[count++], 1, 1, f) == 1)
> +               ;

What's the point of this loop, why can't you read sizeof(buffer)-1
bytes instead?
(note that the loop also does not validate the buffer size when reading).

> +       buffer[count] = '\0';
> +
> +       /*
> +        * atoi returns 0 on error. Since we expect a strictly positive
> +        * minalign value on all architectures, a return value of 0 represents
> +        * a failure.
> +        */
> +       ret = atoi(buffer);
> +       if (!ret) {
> +               fclose(f);
> +               return -EINVAL;
> +       }
> +       ctx->minalign = atoi(buffer);

Why are you calling atoi() twice?


> +       ret = malloc(sizeof(*ret));
> +       if (!ret)
> +               return -ENOMEM;
> +       ret->type = NODE_LENGTH;
> +       ret->data.length.length_of = strndup(len->data.identifier.start, len->data.identifier.length);

This strndup() call may fail.


> +       if (!consume(p, TOKEN_RBRACE, "expected '}'") || !consume(p, TOKEN_SEMICOLON, "expected ';'")) {
> +               err = -EINVAL;
> +               goto fail;
> +       }
> +
> +       ret->type = NODE_REGION;
> +       *node_ret = ret;
> +       return 0;
> +
> +fail:

parse_type() may allocate strings using strndup(), which also need to
be cleaned up here.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DUJsV1ibxSf6D%2BQU4ds1mHUG77NWJ5TR3sVs3f696RgiA%40mail.gmail.com.
