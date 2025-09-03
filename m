Return-Path: <kasan-dev+bncBCCMH5WKTMGRBNMX4HCQMGQEHFIXTGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 62A95B42314
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Sep 2025 16:07:51 +0200 (CEST)
Received: by mail-pf1-x438.google.com with SMTP id d2e1a72fcca58-7724487d2a8sf6252966b3a.1
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Sep 2025 07:07:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756908470; cv=pass;
        d=google.com; s=arc-20240605;
        b=NILtupbD7Bx9fUwy/xbsK8atxmN6/4N0MSnh2Z9yEgWu4uFmNKBwo1i6AQ8Gom0AqU
         eWN/DQWeFXCJUWMxiDV2+63OgxlkDy1VkS25VjloVYLFQVPHFOAQQfR3u3WBgorUXGzc
         LxEuO6RAZoe86D49TVXjz1PtL+HkR6mdPXGr8+llFzntPZiVQjsF1F3+3s114qKmZ5st
         VC4ax7hSwb0c6oxF3apPweOZHl7/bR3bOY6X6u+mgPfrHg299uR65YIo0Jf+/p8nUL7O
         uDemYmKPcOWyGLi6pSRyZ3mQGnlbur1fpgM5NX8m8W9Fy1l+jaL6ZZaTYpEvTLDurWaW
         k99A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Kgn9j3tF9WLQKuReF0uaAeaNDKENYJB4gS1j7Mts66w=;
        fh=rIR3ElPC5XzHDkaH7DBzC0smPGEKMdT6p2vwmjS906s=;
        b=T7Y5h/TGhWjUJ8g/sSm8yOJSy2JrxLLj8LYrJERwPkgfg0RVVnzAhjBGJ2nhQfBJuR
         R48Ygc9csc8cs+bpEmqq6twHt0NIcxJQ3WtWupp9+65nUnhAKgHtGOESk0kl5N5LnyUw
         rPAC0buk+ysIXxr+N1lZoNcLUfJx+q0eGgC4T6UUlay7moAgqz0LbJ9qylQYnPfU7I8i
         wsyTQ/yr4rV/3a3dkUnzS3at7zTUU1LsAYI2ALKRLKITvBEUSPv4Gbp/b75Gqd3evHyx
         Sf+fzc7qJnk716ABKT/mg5d1yINOIKw+2X8BMpj9X4X2UVxLdOu58LYQg86VeZdntc/S
         VSaQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=iHfgL129;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::52a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756908470; x=1757513270; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Kgn9j3tF9WLQKuReF0uaAeaNDKENYJB4gS1j7Mts66w=;
        b=YP2LMbJFre4iBC9gvdW36as6xqIsTykGYtAg8JTunW7ERwa1UjEMRLd7Xd6Vf7682K
         zRp8GMAhbYfSjLiOP9CaWbhNMRYzFWRCw/wlcjz8UVrA43l32wKZgTWgo7f3wnFI23TJ
         TiRKpG4UDky8lIKm7XJD/YNSW+s1zslYYUVOPczNpbLjZ6GiiUpv7VGdHsCw1yLTI44t
         uSw9/Ks8vdn2TuaMz7A3DOPvWoMFaZu67C6oXmPMoPQaxeN3rJQDv5ezstWGlAIogN6I
         9Z154eaDKCNbmqFFPw6/avWYy6MHvV3zQ4shjOOvmQUz1jH0CFQBUM7BfrZHWyibT4L6
         OlzA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756908470; x=1757513270;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Kgn9j3tF9WLQKuReF0uaAeaNDKENYJB4gS1j7Mts66w=;
        b=iQb54EgistQQPJ+jguok10RbSvoGizkdIHcdJwT9KhLo7/ve7hLHwjUfiYt9ngxUZv
         Y41kip1XS463ZcHvqCnJMp4y1/HfjVUWTyDkAPN6P4tlpr1NfCP9jTWkLhxUQVFcsW/2
         6YJrBJpVAUQl2IlffjqcaCdD8X80RrAQQgNlmg/cTt2217p+GC8PRRiCsWkzLkFe34Fi
         TgnwHB5VUzX9eSteS42Gx/X7drW9lxVcG9QiYx49tEDFu3fVJAHYRxv5cP8omj0ajBSu
         7hyWG6MjJ+1qowVGGzdM6g+/o6BbCeTsJnfZbYTaBnTsB9dJOq+454si933LeY26qKxJ
         N/BA==
X-Forwarded-Encrypted: i=2; AJvYcCVRrg8ebCGbfOyFBy5B+JenkxMZo2pJ1Hux/zqk749ZZ5cz+JpdVpAlF5vLkb8mkFZFv4UXVA==@lfdr.de
X-Gm-Message-State: AOJu0YzmKJF9uM6OJSZVNqsR9KkjFdG2Q1v6BvzIbGXzD2LrQSJiAYGA
	6i9k4CA9M1yIJJCmBoqLBKZWZKK4SJnKdaxJ+v6TdxszCgF6buudumsc
X-Google-Smtp-Source: AGHT+IFx+3rvYZK2q6d8kTZVssAe+UXdAGX4tGk2uKiU4Oxnx32KIv0NK5KQm1f/cWoeNAwBIYRoEQ==
X-Received: by 2002:a05:6a00:bd90:b0:771:ead8:dcdb with SMTP id d2e1a72fcca58-7723e258689mr16475469b3a.8.1756908469531;
        Wed, 03 Sep 2025 07:07:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdeBr1+1qNisXmRiXWcjDD/HeFVJD+hp3/Ft9sogR6ykA==
Received: by 2002:a05:6a00:999:b0:770:532e:5fc6 with SMTP id
 d2e1a72fcca58-7725bb7aafels3546863b3a.0.-pod-prod-06-us; Wed, 03 Sep 2025
 07:07:47 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVumL8hhitthrhCnQ03v/Q+FIy+2ObDNZ/UaKXAXNiGpY1BWCzaGibPTGQvBR2CYWejD3SvqA1SwUk=@googlegroups.com
X-Received: by 2002:a05:6a00:2da5:b0:772:8101:870c with SMTP id d2e1a72fcca58-77281019e70mr3276670b3a.11.1756908467670;
        Wed, 03 Sep 2025 07:07:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756908467; cv=none;
        d=google.com; s=arc-20240605;
        b=NulrsrqqJC8EExxoDHC8A4oBzX7hK5hieKAruD2WVMUm5Osty4aOtUZMeDHE1EKoll
         5+WkI7cRrKf8EaDmfrTU9iG5iqRve7gSB/wIM8hsozDmYRHBr4acSkUMh+hQWaHe4795
         MsSTk7lnp+IbR3822F/ql4vCLbc0dwcilUqNhsPCpYol6kyuOdpjKt6qxgOauTSJvqHV
         JVyUk+fZkR1CmXJCEpw3qhY8XdIdDvbhEf3OBLUftwhe382N2S/i3bdp507JRYPIoU/D
         hb9Vc2Kmgn8Q4SH9WMr76UfG0M+6AUbsTZ1c5T2zv6trP1wZLVW7mMZVtcQNiI61zHgq
         //CQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=5K9EI/c+PZFvJEHF5Aa1VFvLskC+dFsbaSIMq7wWgXc=;
        fh=rbdHQi08oDaXRKL/LdsxLtdz+Vvyn0Xi2wL+ua3g9ZQ=;
        b=QKTucyZf9qYKndNL2fNHBjZJrTgJEAcTJ9JBCttqGmXM0BfiCkPkvyb8G3fV0nzvig
         XMl20aiMecWSzIL8ya9DW+zmGq1yd7aVf/3pjGNPJUZ5aZp1gWZpK1A1jT23KEp4SJIE
         JSUFvAzFHwt1C2TDs6lJELb35ia5wZ2fWGVGS2sw3/7ppDaX9JgLVfyL+OPrxmj+V+Ps
         tEcFu3G4vYS6HxveNh63tEhHT5Zu0LVjQ3VPAPdMRMcW4FpgMUcArO2/G7C0HW/v4D42
         zc2gK5k68Cltv1eieiIoLoNis63dO/++DmpZGZgrO/DlUimVB58iZA7rlihXLXG5tDVA
         AAZg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=iHfgL129;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::52a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x52a.google.com (mail-pg1-x52a.google.com. [2607:f8b0:4864:20::52a])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-7726452229asi295226b3a.4.2025.09.03.07.07.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 Sep 2025 07:07:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::52a as permitted sender) client-ip=2607:f8b0:4864:20::52a;
Received: by mail-pg1-x52a.google.com with SMTP id 41be03b00d2f7-b4755f37c3eso5714466a12.3
        for <kasan-dev@googlegroups.com>; Wed, 03 Sep 2025 07:07:47 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWUaMsYuKPINQLIWDmCjxQj3FmmfCRcACzNtmBY3MPuqlI0dPucvXXt06nRkbqCvMvkzfayF4Lvq3s=@googlegroups.com
X-Gm-Gg: ASbGncvTI3Dp9REbQ3+QQZ0fNbxPspkgkZgC/yiZU+/BBgdr5XYHsZtJdFPdDgutUDW
	lVEggtJeslgVXcYjRKWSr6J2h+syiULieyUTU8tQAKRuRC4uGKtzSxmTBjuiSnPlVzWCE7Y5Def
	hG1+SylqtMO9fKF2qle0KqRogqTPeb9rhXwAR1iY5sJhzbgRR881Jkago0rLlCLzhBqDUtsGaZ6
	9Xgc9y4gpUjphzwcb9IJTx9IbJHula05FyHbm6yPvhZWZvyhMiWyw==
X-Received: by 2002:a17:90b:2888:b0:327:ad83:6ce6 with SMTP id
 98e67ed59e1d1-328156bab71mr18212350a91.21.1756908466847; Wed, 03 Sep 2025
 07:07:46 -0700 (PDT)
MIME-Version: 1.0
References: <20250901164212.460229-1-ethan.w.s.graham@gmail.com> <20250901164212.460229-5-ethan.w.s.graham@gmail.com>
In-Reply-To: <20250901164212.460229-5-ethan.w.s.graham@gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 3 Sep 2025 16:07:09 +0200
X-Gm-Features: Ac12FXz0U-3N7wPl6bYh7KGL8GiZ-rYE3Roev_WD4ikilRDTuvPr9ZMXra7VBOo
Message-ID: <CAG_fn=XxRoZJtxKJrLGTTV42H7gDMFEaQZiYQ+nFgmhexzgW9Q@mail.gmail.com>
Subject: Re: [PATCH v2 RFC 4/7] tools: add kfuzztest-bridge utility
To: Ethan Graham <ethan.w.s.graham@gmail.com>
Cc: ethangraham@google.com, andreyknvl@gmail.com, brendan.higgins@linux.dev, 
	davidgow@google.com, dvyukov@google.com, jannh@google.com, elver@google.com, 
	rmoar@google.com, shuah@kernel.org, tarasmadan@google.com, 
	kasan-dev@googlegroups.com, kunit-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, dhowells@redhat.com, 
	lukas@wunner.de, ignat@cloudflare.com, herbert@gondor.apana.org.au, 
	davem@davemloft.net, linux-crypto@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=iHfgL129;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::52a as
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

> +       fd = openat(AT_FDCWD, buf, O_WRONLY, 0);
> +       if (fd < 0)
> +               return fd;
> +
> +       bytes_written = write(fd, (void *)data, data_size);

We need a check for bytes_written == data_size here.
There's no way we can use a while-loop to ensure everything was
written (because the debugfs handler expects us to write the whole
packet at once), but at least a sanity check won't hurt.

> +       err = tokenize(input_fmt, &tokens, &num_tokens);
> +       if (err) {
> +               printf("tokenization failed: %s\n", strerror(-err));
> +               return err;
> +       }

I would probably make tokenization part of parse(), but that's up to you.

> +
> +       err = parse(tokens, num_tokens, &ast_prog);
> +       if (err) {
> +               printf("parsing failed: %s\n", strerror(-err));
> +               return err;
> +       }
> +
> +       rs = new_rand_stream(input_filepath, 1024);

You probably need to destroy this stream after use, like you destroy the buffer.
Same for the tokens.

> +
> +int append_bytes(struct byte_buffer *buf, const char *bytes, size_t num_bytes)
> +{
> +       size_t req_size;
> +       size_t new_size;
> +       char *new_ptr;
> +
> +       req_size = buf->num_bytes + num_bytes;
> +       new_size = buf->alloc_size;
> +
> +       while (req_size > new_size)
> +               new_size *= 2;
> +       if (new_size != buf->alloc_size) {
> +               new_ptr = realloc(buf->buffer, new_size);
> +               if (!buf->buffer)

You should be checking for !new_ptr here.

> +
> +static bool is_alpha(char c)
> +{
> +       return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
> +}
> +
> +static bool is_whitespace(char c)
> +{
> +       switch (c) {
> +       case ' ':
> +       case '\r':
> +       case '\t':
> +       case '\n':
> +               return true;
> +       default:
> +               return false;
> +       }
> +}
> +
> +static void skip_whitespace(struct lexer *l)
> +{
> +       for (;;) {
> +               if (is_whitespace(peek(l))) {
> +                       advance(l);
> +               } else {
> +                       return;
> +               }
> +       }
> +}

while (is_whitespace(peek(l))) {
    advance(l);
}

> --- /dev/null
> +++ b/tools/kfuzztest-bridge/input_parser.c
> @@ -0,0 +1,373 @@
> +// SPDX-License-Identifier: GPL-2.0
> +/*
> + * Parser for KFuzzTest textual input format

Some description of the format would be useful here.

> + *
> + * Copyright 2025 Google LLC
> + */
> +#include <asm-generic/errno-base.h>
> +#include <stdio.h>
> +#include <string.h>
> +
> +#include "input_lexer.h"
> +#include "input_parser.h"
> +
> +#define MAX(a, b) ((a) > (b) ? (a) : (b))
> +
> +static struct token *peek(struct parser *p)
> +{
> +       return p->tokens[p->curr_token];
> +}
> +
> +static struct token *advance(struct parser *p)
> +{
> +       struct token *tok = peek(p);
> +       p->curr_token++;
> +       return tok;
> +}

It would be nice to check for p->token_count here.

> +       region->num_members = 0;
> +       while (!match(p, TOKEN_RBRACE)) {
> +               err = parse_type(p, &node);
> +               if (err)
> +                       goto fail;
> +               region->members = realloc(region->members, ++region->num_members * sizeof(struct ast_node *));

Missing a NULL check here.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DXxRoZJtxKJrLGTTV42H7gDMFEaQZiYQ%2BnFgmhexzgW9Q%40mail.gmail.com.
