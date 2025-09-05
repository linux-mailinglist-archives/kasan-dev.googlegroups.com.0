Return-Path: <kasan-dev+bncBCCMH5WKTMGRBCH65LCQMGQEL6CKQBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 20482B45515
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Sep 2025 12:44:27 +0200 (CEST)
Received: by mail-pf1-x439.google.com with SMTP id d2e1a72fcca58-7727edb9d3csf1800624b3a.1
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Sep 2025 03:44:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757069065; cv=pass;
        d=google.com; s=arc-20240605;
        b=Iw/tCeRQ6/KgPEyAXNa7xnrzZvfPXJN2FPNL0cOtiXgDmD6pqTXphdjFDlt20YkaaQ
         twiZzPxDH05+uAWPppiq7pWOVebmniJdD2MIBKCRIgUHOOZskzkSs2vkVuIhsKe5Q5Ek
         Lh4FE7CwgvhMRkpM4QmMGcYyWh1lACuhd2Vw7tMupIrAz5ex8pL5wo/autFn0BeTpqD0
         BFKihSos1Z3yC4nFSbNbWrLzuh/jr7Yu9Yvnzvq7AjiQ+QAcS0fB5eWjCUwi36UjIykc
         +8Z95vyZfBQemuup1E66l1jbYYBAFD559dcwE003L2JS4Ji9nU0onwgtRyjr7FrIoMOJ
         jrmA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=blbELISnN2Iw2PiS629RUm8gC2LnEPgjMDCFCfvE1d4=;
        fh=m9Ax7rIzaKl6s5qNhylOU/rDW+KvTBziZ49vOyV6ZS4=;
        b=hyaXf2VRlSHxQNm3ygMFeFKsxeKYfUfkg13fQ+Mgka1CWzUyProjC89vJoGjZtzYPs
         khgfbsCJupcjRwpP+Hjm4PrULoJh94GhPsNrTAgpWkhwQSaVJtmy6h36LlgHc5/VMqM+
         +mjS08HHI8O4dVOaueSYukJTM5b6XWXJV32cEg64oxrlLhrJQD47gnfMB3WyUm9/Wjr7
         RFzGFAvbXb5k++nJGz5l5XbraP8C5/Cr6MKxk8cvskuPYJBKqrN3iJfmHv5TlbKG2O9M
         bZGZpN3kPkCXLM3g4syG8apO7AOCIDrH2VWlwh63j4+xIAjBH9yhksDRJKZtl/p5cOD6
         OHDA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Pwz+SrDD;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2d as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757069065; x=1757673865; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=blbELISnN2Iw2PiS629RUm8gC2LnEPgjMDCFCfvE1d4=;
        b=sJU0yySckeYlJHnRwlziKS9s8saj3CRi3xpBvpcdPOAwJKq5N1DEKA/NcyotJuG2sg
         NPB7WF03ikEVs9eCl6rbq+WJKLuDiaWBYCSDB0cIBZCeu29dd5sHRHLeA1wCTVhHAKyz
         fD5iH4k9tuPf2rDJFWFO7myeSIQJTibK5N5kR6Cpar7Ja6PFGN7wdSzVGU74zlB0sX6x
         0aRNaNTSCyKoVYqJBHwPmBvfdqft9I0IQp49upVL7Y0zREv3XFlw/7QLXPwi1gwFNeqS
         aefhSvIZfLI42Qo+avBfJsoEW9TakFghEpJAua79RMitR/SOZBZMRzPJKw6qi0gIrWe7
         EjEg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757069065; x=1757673865;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=blbELISnN2Iw2PiS629RUm8gC2LnEPgjMDCFCfvE1d4=;
        b=ViAqWgiiset8evHr49KOPA/KjTqeYxsyCCd9sa/QpH4zqDMmHjqCR7zVyXFu6EnF8h
         FE/JbjnnUT1f/HYBm4PhdC1qBN4YjbX/XUYmN13I7u+z/zLum8H/z264AsRXdQqtCMDg
         Ty7FobNBQzO/e/JElFFJNvL27T3wEeYiDOMdtQDyUzPye48RS+Pbg5nIofgY2T/oAIgK
         9sXXHxwlLZ0ZCSs8FicJYqUCNpVKugr7s+c6vgg5KsLo2NyZbc3LabVLTlBD4RT+ZtuM
         G9P02cR9YSykmhNhvGnNHG+TwyCy8lZbyeFfIFLJk2HjfmKU5jk5XVaxN3S3A5H5VVlp
         SEjg==
X-Forwarded-Encrypted: i=2; AJvYcCUjXl1/1BcFxpevkF5AT0h4X+0NgGKZIIYk4SilI8ZHV/xYY+2vXM2KPX1kUtgkkeCoCXOPSQ==@lfdr.de
X-Gm-Message-State: AOJu0YyJfoHWCKMJlvBQguAgcjdsLd0KhVbSt1HFSN3DWOztLs6O5nG9
	wbgxSnj/7iSFwQXG+VMs9GusO5H0curtkgQRWWklt20f05cZuKfcu0hR
X-Google-Smtp-Source: AGHT+IFaP5P9kQOk/4RpexuIPKcQwPrCivkezsKaMX5sX0FEdrHzL/PHaHHxDhLnpI82YBhcxX/pwg==
X-Received: by 2002:a05:6a00:130d:b0:772:3ef:369e with SMTP id d2e1a72fcca58-7723e22cf8fmr28950835b3a.11.1757069065308;
        Fri, 05 Sep 2025 03:44:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdaeUA8QIgo1t60+MiMMDVT7SA+AGAkpXsC/RUpS0qFHw==
Received: by 2002:a05:6a00:1c86:b0:772:6b0d:37ce with SMTP id
 d2e1a72fcca58-7741f09f4f6ls510881b3a.1.-pod-prod-02-us; Fri, 05 Sep 2025
 03:44:23 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWKTPDvTZ4NJqgJTM8CPWrfhQqSskBzC9ZFDDl4TKdluVZTQQUNUnlCNuu4f6wAbCl18ZNQEvZALio=@googlegroups.com
X-Received: by 2002:a05:6a20:748e:b0:250:595e:a69a with SMTP id adf61e73a8af0-250595eaadamr1956855637.41.1757069063552;
        Fri, 05 Sep 2025 03:44:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757069063; cv=none;
        d=google.com; s=arc-20240605;
        b=aOsbkjru9hY08pRnDurL6MnTe/3w0bjMpkC4N+wQYdlyiN2lCfKzeZ/a169C8BDVng
         o+gfmBH9kaV7UzyUZ+SfzxcLFDDZPcvD6qcS8BdhmzfQJ6drEK4Bjf3a2wnDYKMI9F0c
         is1JCmsOJvAJkS6l8OyGhi5xcbACKZoGLghT+QZD5H+tNHEzfwcfeNjfrHCp/OmG6S5A
         C/JTT6qHsZ2BDJPz6q7cucPPEMPEYTkfItfId5IjuQ8LlHvRKReGScVW/8TbM6kMVmo4
         paVL/4zjz1xlp4oltcVIfHxXl0F+rYSm3O3MguO+g74yLv8fhX/BznaUcKeFDT0AYNJi
         X8rA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=tJ18ogS6OfuTP1EQiRfSY6yIXK3vsX3youWzsSBm03k=;
        fh=xDa/juKqzTiXfO1NZDr0h8Lz4H398HOZAZrotaviJ7s=;
        b=hj+Inho99VjL4e/6dciXWzwuan99H5eEQNotR3ZvnNTrBlaK8UURNYqTEn5YqocZ4o
         1Nif57fjIsz1j98XRgH4Ji5x7QJLjqU3GIje//uBgzPtqy/PxfQeVWwupP19TQEx+RMT
         7j0DV0iCqxt5ryuIqIA6s66mwt8j+/RcOWT+jfpMtBSuvA4COqQvc1yvSp3D5inytU30
         VCRoMzQfSkBW2UJnfE00NOTKk0btzZyRbM+wMmdSZkime1gl5QiuMpnAvLnIGtAHaiZp
         LwihEBJ0N2W5gCwS8LyDsMeL3Ik7gRbrwH8Yx+TV3gmmHbsLls2TQRHZxpAwCki7wBxn
         bbLg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Pwz+SrDD;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2d as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf2d.google.com (mail-qv1-xf2d.google.com. [2607:f8b0:4864:20::f2d])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-b4ccf7a0dfasi796938a12.1.2025.09.05.03.44.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Sep 2025 03:44:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2d as permitted sender) client-ip=2607:f8b0:4864:20::f2d;
Received: by mail-qv1-xf2d.google.com with SMTP id 6a1803df08f44-722d5d8fa11so16561846d6.3
        for <kasan-dev@googlegroups.com>; Fri, 05 Sep 2025 03:44:23 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVUduhboxUsp5pMr6G54RwqFmwwhUT0n1eZNOyazIEhN+ELi8vLY39rmaR5lbrGk6bpcgXrexP8yKk=@googlegroups.com
X-Gm-Gg: ASbGncs9BWh0CBlL6ZY0aGUsGHDXwT+AYF6QUuMhhuGmFikzn/1PvjA5CiJ8Gnh/U4t
	0myVkKDjdg41RXlgBPGM/B84mUITlbWp6I3lJs67Lcg5Rea4NzHEMA1BxiwxqjxR7f3rE5jbmLx
	tth/NUjPiDEX7l6mP68Il0XCa4O8ZOkLK41eGl04+8AapA2q7rOQzmct7KyAbVF/Td8E5H5g95k
	XVi1d5YdbTjsBKNgxnNbP0XKZtrbx+3Ku8tvXFjATD2ip1LS3fUvCi8f8dOvErBaA==
X-Received: by 2002:a05:6214:23c7:b0:70b:a189:a571 with SMTP id
 6a1803df08f44-70fac7a01cdmr71754206d6.25.1757069062247; Fri, 05 Sep 2025
 03:44:22 -0700 (PDT)
MIME-Version: 1.0
References: <20250901164212.460229-1-ethan.w.s.graham@gmail.com> <20250901164212.460229-5-ethan.w.s.graham@gmail.com>
In-Reply-To: <20250901164212.460229-5-ethan.w.s.graham@gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 5 Sep 2025 12:43:45 +0200
X-Gm-Features: Ac12FXwrVWcwse0FO0oj90oXgii4UalASzAKNOgq4n0I9KmYMeRdWc12CPAmKB4
Message-ID: <CAG_fn=VXxaGd4QC0jHzwFg88HuaOFV4K+_tdzrhqW+UoTk-L6Q@mail.gmail.com>
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
 header.i=@google.com header.s=20230601 header.b=Pwz+SrDD;       spf=pass
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

> +static int invoke_kfuzztest_target(const char *target_name, const char *data, size_t data_size)
> +{
> +       ssize_t bytes_written;
> +       char buf[256];

I think malloc() is better here.

> +       int ret;
> +       int fd;
> +
> +       ret = snprintf(buf, sizeof(buf), "/sys/kernel/debug/kfuzztest/%s/input", target_name);
> +       if (ret < 0)
> +               return ret;

Please also check that the file name wasn't truncated (ret >= sizeof(buf)).

> +
> +       fd = openat(AT_FDCWD, buf, O_WRONLY, 0);
> +       if (fd < 0)
> +               return fd;
> +
> +       bytes_written = write(fd, (void *)data, data_size);

Not casting data to void * should be just as fine.


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
> +               printf("tokenization failed: %s\n", strerror(-err));

Please use fprintf(stderr) for errors.


> +static int refill(struct rand_stream *rs)
> +{
> +       size_t ret = fread(rs->buffer, sizeof(char), rs->buffer_size, rs->source);
> +       rs->buffer_pos = 0;
> +       if (ret != rs->buffer_size)
> +               return -1;
> +       return 0;

Note that ret may be less than rs->buffer_size if there's an EOF.
Keeping in mind the possibility to pass files on disk to the tool, you
should probably handle EOF here (e.g. introduce another variable for
the actual data size).

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DVXxaGd4QC0jHzwFg88HuaOFV4K%2B_tdzrhqW%2BUoTk-L6Q%40mail.gmail.com.
