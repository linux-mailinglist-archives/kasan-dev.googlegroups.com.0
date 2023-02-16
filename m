Return-Path: <kasan-dev+bncBCCMH5WKTMGRBLH2XGPQMGQECQO5DXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 13C20699CBD
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Feb 2023 19:59:57 +0100 (CET)
Received: by mail-ed1-x538.google.com with SMTP id g14-20020a056402090e00b0046790cd9082sf2748673edz.21
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Feb 2023 10:59:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676573996; cv=pass;
        d=google.com; s=arc-20160816;
        b=HfreQyPvOoC26RKAMd3r7JRsJqhn3Aq03d406j4U6Y5sHSWqKwzUYmgjd8wHtQ+z2w
         xUxPe5e+8VnHgVcS6v3k+NN5yDCoZdZQummd0y/J4/R4eloxCHTAOIToA+npumUS74Kd
         1LTCA4FZ3/FeXJCoALrVGeSUgdDCj05hm4OZGBVW8jeHF6z1Zf7HVGQuS6qnp0+Eqenw
         O+8dRUDo+2E7kQkX/a8+i3huPgkOJh1ADmGu8MtZjFMtak2DQecodQtNiEnuPRzeLqC5
         1jhXJR1ZHWzHuhnRZ6NTjO9TqUzHC/f+9giVjoh49B4Aard66ru5c+fh6X0qAGpIdTxM
         PO3A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=I9e081RpywszwjkgbgxjeoRhxksnORquklw9eKYtrwY=;
        b=NevjWXGreg8gCQaltMOPOy01LjWOinEUigFdC2OAVGc+dyopMVYumJYJmdDNT+CQ2Q
         ZX0HIlrKM4F2dNNcEWf3zqxFjuGsWjUCmDSNC7wsRBghjw1arrIqnQSMe07pdY8gKJdQ
         mZvbgzuS1Ej68ENrIsEN3MLBEAC6G2ifA3utaloH5D4TUw5FPPpIxHXaKjSdTxRpgvOl
         tclB0Z03nWRizDw+HlFTjVkd9ngIa4vnjHfEMmrLtkWWimLWUwRgp572/x/ev0RZIk0N
         LCeHpjfU3/CBPGrZcGK2ybvcJRF7eMIinZ9uGwPn+djMxTb1SKpXEeGtw/UMkH5w0mug
         IIfg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=pAvCpLSI;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::433 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=I9e081RpywszwjkgbgxjeoRhxksnORquklw9eKYtrwY=;
        b=M1levenZ0U9pJtdvhCdr2ttybtIA1sJr2mfGDfFzwHuLU1EaZqoR0ns/k5q5CiZwk8
         lusBcRGEVEke3aiSxqASnNJx/X3rW3c3bDExazzsbY9oESchP0vh13/Pr63a02aCbjk/
         /srwFBLCqkFqMZLaGmtL/1y2w5KY972ntbHcfYhB6lz5kf/1KiiM7YZBCewds/TJOnaJ
         ngsohVG8ybxIuPltbq2bLsUqucdByrKCHpwxQazu6iYlcWXVzkbBEsnP4I8GNiSFeaPk
         VhOvBOyCoTfqLtPAwrSv9onIupsLF8KVnIaoTohD4TnZMp8s5tphrs/wLfwfQpyImAFo
         OpQA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=I9e081RpywszwjkgbgxjeoRhxksnORquklw9eKYtrwY=;
        b=rnW4NwwYXSQjUU0t48GlbEmm/NIS8jfWOA694B8l1EWd07gYJiONFtn2Vbs1KcwJx/
         rgkwqaL1WnaqLrQN3DjL43/wlWMe2vlEZnLJ/jFMTC7bh9lriKVQdKq1sx4gqsIPACkm
         U8lA/x6luEDJ6GEWTqzgik3GrR0/nj1FzLNfQVOg33N/fkzjFnnoy/yQ51zshvwaxrsX
         fTA3HzHpvpYGYWrFs0gRGV34ieMceEBF0NKd9c3mh1Q9w+TpZ9/BYH9RshcFrNP1PVEz
         5Ws9Ndev50rMMqFcpjJ5tqF46DTQYx0KgfA8xIg10ZizQKoS3lC6V1PRlmc7+2y7ueUM
         84CA==
X-Gm-Message-State: AO0yUKWRNd6KhBf4TAFE88Ngxmx8oE085EV9/f8UzV0jX7Hd8C8oQVQ+
	n78WUN2H6QFDZ9dB7kdT5TU=
X-Google-Smtp-Source: AK7set+iU2MNpb5QlQK/qFbEzKillurjV8r09/XXZpS5xWZm+7CECC0b4iaqqQOC2WFxInaG8nLvDQ==
X-Received: by 2002:a17:906:9f25:b0:88d:ba79:4310 with SMTP id fy37-20020a1709069f2500b0088dba794310mr2415564ejc.0.1676573996528;
        Thu, 16 Feb 2023 10:59:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:ee17:0:b0:4ad:73cb:b525 with SMTP id g23-20020a50ee17000000b004ad73cbb525ls1274938eds.3.-pod-prod-gmail;
 Thu, 16 Feb 2023 10:59:55 -0800 (PST)
X-Received: by 2002:aa7:d885:0:b0:4ac:b31c:83d3 with SMTP id u5-20020aa7d885000000b004acb31c83d3mr6459309edq.14.1676573995180;
        Thu, 16 Feb 2023 10:59:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676573995; cv=none;
        d=google.com; s=arc-20160816;
        b=WxOHOvssuD6BqHOoQWENC1e0WCSAuVLBEX2t60c8gA++V2Kh4ugeFDZelQsxNGuixz
         c/09t3kwtvDnp+ndfnAaKk8e2+7hrV+Kk5pO7y+zf7iVY/ux0BhSnhclUuaDwPMKSbig
         Lam0ybykdQxGCMNqNvbIeAGFMuIUjc98xT8k6ghaSGZMu3NZPTLTEo7c8bIa/g8L4TvF
         tVzF4KKOFDIc2B7y6vqrbR8cPDjISdC/FsppcrJIJFgnHufqTnuL8BzpQRw8DI1BWZai
         dKSGVqYVj8BWdvv41+P/0OGM9eg+2q3lj7cX/jz2iUEHWDowEj2NPGEM4SW01RvtjU90
         n4yA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=16NwX6E/MJZLYXtvH88vb9mQe/rSJJo8cnIM1GgMvfg=;
        b=1K46JES1iAFpUaCMDa3rz+qIthqa4BqoBqFijCjBhuYhDLywLhWElpBlkEs9NeDwT7
         +XAD8iMxfGOOGaqtpE21ul/XwRJ3L0a0BgcwM3j09cbZBe0y90A4mFo2qHwfb8JLpOns
         LISh4nm9llHygIapiSPefd4yU3iqOC2EoUbyJ+JxFH45s8Wdd3R4c6stPY0j2NDuICNC
         IXLug+e5pFofLrHCm8VJ7YVnIfyjt8naDxPWntgLRJiQmyn6gGV8cL/ZjLwwR6ddRxeV
         sVUbnwhJ5sfgxa60GvQygbfT4O4Hh6C9ZCt5bV0O/ASJ5OAFwkciMWMaqN5xQADImY3I
         0qfQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=pAvCpLSI;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::433 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x433.google.com (mail-wr1-x433.google.com. [2a00:1450:4864:20::433])
        by gmr-mx.google.com with ESMTPS id i26-20020a056402055a00b004acb5d81250si120978edx.3.2023.02.16.10.59.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 16 Feb 2023 10:59:55 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::433 as permitted sender) client-ip=2a00:1450:4864:20::433;
Received: by mail-wr1-x433.google.com with SMTP id d4so2718014wrj.1
        for <kasan-dev@googlegroups.com>; Thu, 16 Feb 2023 10:59:55 -0800 (PST)
X-Received: by 2002:adf:f6c6:0:b0:2c3:ea81:64bb with SMTP id
 y6-20020adff6c6000000b002c3ea8164bbmr152263wrp.479.1676573994742; Thu, 16 Feb
 2023 10:59:54 -0800 (PST)
MIME-Version: 1.0
References: <CA+G9fYvZqytp3gMnC4-no9EB=Jnzqmu44i8JQo6apiZat-xxPg@mail.gmail.com>
 <CAG_fn=V3a-kLkjE252V4ncHWDR0YhMby7nd1P6RNQA4aPf+fRw@mail.gmail.com>
In-Reply-To: <CAG_fn=V3a-kLkjE252V4ncHWDR0YhMby7nd1P6RNQA4aPf+fRw@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 16 Feb 2023 19:58:55 +0100
Message-ID: <CAG_fn=VuD+8GL_3-aSa9Y=zLqmroK11bqk48GBuPgTCpZMe-jw@mail.gmail.com>
Subject: Re: next: x86_64: kunit test crashed and kernel panic
To: Naresh Kamboju <naresh.kamboju@linaro.org>, Peter Zijlstra <peterz@infradead.org>, 
	Marco Elver <elver@google.com>, Jakub Jelinek <jakub@redhat.com>, 
	Peter Collingbourne <pcc@google.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>, open list <linux-kernel@vger.kernel.org>, 
	kunit-dev@googlegroups.com, lkft-triage@lists.linaro.org, 
	regressions@lists.linux.dev, Anders Roxell <anders.roxell@linaro.org>, 
	Arnd Bergmann <arnd@arndb.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=pAvCpLSI;       spf=pass
 (google.com: domain of glider@google.com designates 2a00:1450:4864:20::433 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

>
> > <4>[   38.796558]  ? kmalloc_memmove_negative_size+0xeb/0x1f0
> > <4>[   38.797376]  ? __pfx_kmalloc_memmove_negative_size+0x10/0x10
>
> Most certainly kmalloc_memmove_negative_size() is related.
> Looks like we fail to intercept the call to memmove() in this test,
> passing -2 to the actual __memmove().

This was introduced by 69d4c0d321869 ("entry, kasan, x86: Disallow
overriding mem*() functions")

There's Marco's "kasan: Emit different calls for instrumentable
memintrinsics", but it doesn't fix the problem for me (looking
closer...), and GCC support is still not there, right?

Failing to intercept memcpy/memset/memmove should normally result in
false negatives, but kmalloc_memmove_negative_size() makes a strong
assumption that KASAN will catch and prevent memmove(dst, src, -2).

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DVuD%2B8GL_3-aSa9Y%3DzLqmroK11bqk48GBuPgTCpZMe-jw%40mail.gmail.com.
