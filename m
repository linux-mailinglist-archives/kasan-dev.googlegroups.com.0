Return-Path: <kasan-dev+bncBCCMH5WKTMGRBAEXX3FQMGQEQWF45YY@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id AOW9Kr2lb2kfEgAAu9opvQ
	(envelope-from <kasan-dev+bncBCCMH5WKTMGRBAEXX3FQMGQEQWF45YY@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 16:56:45 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3c.google.com (mail-oa1-x3c.google.com [IPv6:2001:4860:4864:20::3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 47C2446DD2
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 16:56:45 +0100 (CET)
Received: by mail-oa1-x3c.google.com with SMTP id 586e51a60fabf-3ff59b0f2ecsf9346765fac.2
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 07:56:45 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1768924604; cv=pass;
        d=google.com; s=arc-20240605;
        b=kI4VvL+IXBCrqKgsCdm3iMB4cQ6Pgc5JJmM4iSo2/LRufmGkuWo8Yn8+mHfpzZEp97
         X0qazDvSd3kbXdQj/shL9FdHk1RamZDnf7ocADzZ+XXpQ4ujU4dwkKr5t0GFZH6W7NHe
         LcJcaaiHIAt0lCVX+q7zkPI0/IA9VtRBF5+mHc7Obx0Zk2j1CvRpoa6YBMfIR4KhCZOV
         rAlIVeW8ZyTFcrMybg8Z1rMRya/b7S0+2I4sMIGoE8+HGEfFfDT5qdSOO8Fh9XmdzZa7
         f+XYtQvKsUiMSH0uXo3ReYy+XPonaXrXRxyE/2pZxAvbb2/7U2GOKmIg6oblHfmletdW
         iuGA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=1eXh4SR9j9w4M4LpPGYixd3Yr7765NZJWu5+4lcZClE=;
        fh=7WsHqviGjCos46DlW/eqJJe2pnuasPZr9I6N4Vbykuc=;
        b=GCQGjV5Es+wZXkACDvJed+GzlWTcjPowZtyXbEwkfRwTVigN3NWrBhq64V62qiT8Cr
         ZTMSJWRVhnwdypJX/1z+sSZyzS3NllCvpCi24h7qZpcBqNmFPu9d0nMNuDs+ga4R59u0
         fFUnMGykEpnY2YyRu7FBgEbb6j5QSmp+HdIiv+TGTzdpGlb/jMbhJAeRFkO/9QKytEoP
         83lwSWKl9+b43Gxh0bcb+UG7DZjH5NFv8tMDBxdbYjCzU3MjufWgXGWnNlmQzGfv2KWZ
         hX3h9pybSYwAHE9dQO+Oj5XMOGZ2txfa0giCqJ4uSoGZS7qPcwlqe8ibYDJxDNnzVA7M
         74gw==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Qt4UfaY3;
       arc=pass (i=1);
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768924604; x=1769529404; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=1eXh4SR9j9w4M4LpPGYixd3Yr7765NZJWu5+4lcZClE=;
        b=XJ4GGoPMJw78YXOVhKyCqacIfI9y8Mb/SsLyBLBE/p4z5LAjLyu+t8LQ9QzICe7krW
         tOZdVzNZKmkSORGQyEvOOzJhLWQ9hYcANu5HbOaqi8yX4whFtPweEhHbYsMTXzBJ93Bi
         l5N54V/TZvb6U5WTa0/NO+Z14HgfT2hY+LEXS99oRSyo4PVXM9eSEd43HY83UlK4tjAt
         7SiHeCQUBbMvx6cLVaLtDkeqDjB71i0l/eyZHgh/ZWbQHN5bzlDMeL5QOEhaImKi/hUX
         9aC0NkyBVfFWyQlEHDC/bbu63QfQLeaw5EZPPxHJeJ5erJJOZ4Oc6eRCNOl9s3oS9u7m
         TaTA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768924604; x=1769529404;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:x-gm-gg
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=1eXh4SR9j9w4M4LpPGYixd3Yr7765NZJWu5+4lcZClE=;
        b=Cb2TM1C3s1Tb9vJBCiu2GE3zaQj4fqNbXKyc4K2C5k2hLY7HgmBnGytZSb/MkcFs42
         ZqKZceBzeZ8VxqdFfl+ZSNtIR2BZ/WJcqd5kF6xTQG5fAQPFHt9nK5bFTQ3TKSGeOFgD
         YiIoPvmppLhwvIl+drFEKKHmtJwPhAsX5bR3q43zdJ3QHDTbU85QjYtjm7D4EUAa8eTP
         eL+HWAzKnMn/zYa/6QRuQoztboLzcoHl50lg18ul0rd2jGxARpmi6BzsmOZqgECXg9lw
         QDpMcOdf+gUq60PIbyJLf4UraYEKS3bBRyKHEMOn5Yfj+4Z7mvEoNpnwhT+f0VpWRZ4g
         60KA==
X-Forwarded-Encrypted: i=3; AJvYcCUL3ynKH2JtMxvpnBGBfK7CxNqV6BqFmcFNtIw20fAUjkLfRXX4iuxcYPhWM4OaJ8GVKigHtw==@lfdr.de
X-Gm-Message-State: AOJu0YyYQfUaXWPHTmgfFUB/ZhX6pssE0fa7TRUWCMv2CUMYrpzYZvzf
	kqrS1DhaG87hFVHMq7d8+gn/P0WxYIV+GnLmR9fjUB0DRD+7iojWNglC
X-Received: by 2002:a05:6820:1ca1:b0:65c:ff20:a3b5 with SMTP id 006d021491bc7-662b00f159amr709954eaf.77.1768917889076;
        Tue, 20 Jan 2026 06:04:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HMrygDKoJUxbsUCI6e0KzB7Fg6TOwWIlD/2UT/3lWnZQ=="
Received: by 2002:a4a:a889:0:b0:659:96f3:5ea5 with SMTP id 006d021491bc7-6610e5c53e3ls2326399eaf.1.-pod-prod-08-us;
 Tue, 20 Jan 2026 06:04:48 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCWjVXWB+oOV1yLIRluts46BSgdk0BBKkUAIDkkFzQO8wpo6Jt/4P5055BDVyxtjdMQw7rmVasaQ5yg=@googlegroups.com
X-Received: by 2002:a05:6830:905:b0:7c7:5349:4e31 with SMTP id 46e09a7af769-7d140aae196mr782432a34.21.1768917887967;
        Tue, 20 Jan 2026 06:04:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768917887; cv=pass;
        d=google.com; s=arc-20240605;
        b=Oq/m1rhWrS1qY9GKQjCIDwRIwIoVHJht4S9kI7UoKbVqDZslaqliGZe2y77I3ygxY+
         UH3nfo83RfkAOAygvv7ZEvSSh76va2tuKQZ5ly5ttcPhp9jZ4QUfj7nH7hSKWMPulb6j
         vgdfKLX/dQlop1madoQsihuJIdIBKIqIjwj2P7VdHTXgqVU8wS43gBpC06/eQbR0iJzR
         1iFXN7WbQ+PT4W0krw4n73H7bgbLYBRLfRgfj6jgPGgeWKkQdMJ8kj3xRDy4LkIVew/V
         ln41zwZt4oXDvNJPKF20SWBQLnuMxVZit5P9Eg/AlpxC3GZ7x9BHpVC8aKZAqGEY6ufN
         Rilw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=jmM/dV1Q0UanGhFdvF+GkJPZvDrrzI7SS6CZEDHOhsM=;
        fh=OzL6JBrHE51SRH2YstYxoWADmezFtdQyIkKy+esPjzQ=;
        b=Q1rl2i/kkqKcqupHBR0nN3BLsEANodEi/ixnqw+iwtTIfkrSDU44+tfh+nuUhuABkJ
         34b2eqtUNwvvaXN287BPBDWC2GIGvAuXckTfNPABmsJVMZHw2VukTzDJ30UfRNadUArM
         Hs6kPvETXlgdZxEVFj4z9nqDKhLdaYzer0FSkryTu/4hqoDQL2j/QscNbnWwAYYiFJEk
         8urWf/9JwzlAX2IQ5igarGeHQ51zRIwxeD8rEuv2us4rJRhqjHOmbCxjUotfmNHFvWKg
         NI1jlXJKxBKrKfsLFoq52Gz3MOheRaDgeG0D7rSzN6PpJfOHja4jPe5ORSXX/ZqG32vE
         h2AA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Qt4UfaY3;
       arc=pass (i=1);
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qt1-x82a.google.com (mail-qt1-x82a.google.com. [2607:f8b0:4864:20::82a])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-7cfdeffc28fsi500989a34.0.2026.01.20.06.04.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 20 Jan 2026 06:04:47 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82a as permitted sender) client-ip=2607:f8b0:4864:20::82a;
Received: by mail-qt1-x82a.google.com with SMTP id d75a77b69052e-502a26e8711so21724011cf.1
        for <kasan-dev@googlegroups.com>; Tue, 20 Jan 2026 06:04:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768917887; cv=none;
        d=google.com; s=arc-20240605;
        b=MQMpwqbfOTg2CPo9bX+3JAN8hW8YeF5ozpXej0roHSura/GY1WUPNIdyroXYK2pTO0
         t0XZDhasAaYW0uoHC0hI8F8rl7cRbbvdfFOEh36BzeviTPgyly2KAxSGfQJ9qsQnoYlm
         bVkc4ou5L28VpR4MVIh6+lnBOIT0HK4wocWjaLQMWc2C0m9eyJ1xDqYKdCR8PGBLsax/
         icinsaO+E+LjFcd9MdWJJq7wVbBihpzHdDyT1xL7x6uNUU2C57mPk+jlEl6FmFypRrnS
         bZjQt+TG8Qo9CEQE9lAW83NHzecz6Wyuo/NX8yb9DxAvydQawlzxJGOBclurYU5VsxQE
         KmyQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=jmM/dV1Q0UanGhFdvF+GkJPZvDrrzI7SS6CZEDHOhsM=;
        fh=OzL6JBrHE51SRH2YstYxoWADmezFtdQyIkKy+esPjzQ=;
        b=XX+5CB+pjgUtdIAN2GVXJAGaYCQdhzNR2+eAcX6qtRhzflT/dnpJkaxgHjOMWbF3Jg
         xsVYSA4PEr0mMn1TYPaAQfw8QXn2WI4xxRnqMLcv/OKjdlcRUbujaypZgaIKHf5Nfwa6
         kW94f8dsh9pcG73qqkrtxlFiLSBommuWEb+6wVDHJtLbjLCnfPOEqaJAxJVM+3pgr8/n
         xUAH9UW8m7Qf4i9LAV/KUAGRmcSTz9d7g2KxyNJ4tpvE3Ez5UcXJ5dg1O7yRf/IP9i/A
         mZd7OPCUvUlZxoCntDtIzh2mdhZsOj1WlRaiNqdrnNpjqO52CYQAGlul+Fj2yGkVrpF0
         UdFg==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCXIxVkefQ+Fjl2IkGoPUjTtPqw2swI1eTpdq8OOI89e1bw6mVb1iq/M60go5jQjO5whGB6hEpCZG/s=@googlegroups.com
X-Gm-Gg: AY/fxX7OARvcqrgnlYC7kYYENJqaiqK9SuH1xVAe3uTX4lg13Kh86Y2WVuQn6jrxiw2
	2/iMB8Ofrx5zj8FPWDpIuE9JfIfDbDaJP7XywNSryRPrEnr9Sye/lcqWjP0+0gK4bKMy9JVPY+o
	YY2omsS4UcibrhPJXhDtUfIPE+mBZV6G2ZY0a4nlcVg40vwqTGREOZg8gry7eb01RmUvqCb8BQI
	KdFoHStwMhoZfm0qQXRsm/Te04Quvj0yUodZTXoe3P20Q5AUFQorRZW0Jbw2wjrPi6z27A1sNkB
	Ou9D17UPUOpdVzF8pOA5qqXo
X-Received: by 2002:ac8:578a:0:b0:4ed:6dde:4573 with SMTP id
 d75a77b69052e-502d8507492mr21826281cf.52.1768917886535; Tue, 20 Jan 2026
 06:04:46 -0800 (PST)
MIME-Version: 1.0
References: <20260112192827.25989-1-ethan.w.s.graham@gmail.com> <20260112192827.25989-5-ethan.w.s.graham@gmail.com>
In-Reply-To: <20260112192827.25989-5-ethan.w.s.graham@gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 20 Jan 2026 15:04:09 +0100
X-Gm-Features: AZwV_QjNl1xBiyaK93_mkyw1s5efrvsnk9WwoFCUyx7252b7lOOknPIAjr9SWYE
Message-ID: <CAG_fn=XG3sGS-_ioH9ThtQf8TCx60vTJZ8Cj33OTfM7FFW62Og@mail.gmail.com>
Subject: Re: [PATCH v4 4/6] kfuzztest: add KFuzzTest sample fuzz targets
To: Ethan Graham <ethan.w.s.graham@gmail.com>
Cc: akpm@linux-foundation.org, andreyknvl@gmail.com, andy@kernel.org, 
	andy.shevchenko@gmail.com, brauner@kernel.org, brendan.higgins@linux.dev, 
	davem@davemloft.net, davidgow@google.com, dhowells@redhat.com, 
	dvyukov@google.com, ebiggers@kernel.org, elver@google.com, 
	gregkh@linuxfoundation.org, herbert@gondor.apana.org.au, ignat@cloudflare.com, 
	jack@suse.cz, jannh@google.com, johannes@sipsolutions.net, 
	kasan-dev@googlegroups.com, kees@kernel.org, kunit-dev@googlegroups.com, 
	linux-crypto@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, lukas@wunner.de, mcgrof@kernel.org, rmoar@google.com, 
	shuah@kernel.org, sj@kernel.org, skhan@linuxfoundation.org, 
	tarasmadan@google.com, wentaoz5@illinois.edu
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=Qt4UfaY3;       arc=pass
 (i=1);       spf=pass (google.com: domain of glider@google.com designates
 2607:f8b0:4864:20::82a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
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
X-Spamd-Result: default: False [-0.71 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=3];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	R_SPF_ALLOW(-0.20)[+ip6:2001:4860:4000::/36];
	MAILLIST(-0.20)[googlegroups];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	TAGGED_FROM(0.00)[bncBCCMH5WKTMGRBAEXX3FQMGQEQWF45YY];
	RCVD_COUNT_THREE(0.00)[4];
	FREEMAIL_TO(0.00)[gmail.com];
	TO_DN_SOME(0.00)[];
	MIME_TRACE(0.00)[0:+];
	RCPT_COUNT_TWELVE(0.00)[33];
	FROM_HAS_DN(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	HAS_REPLYTO(0.00)[glider@google.com];
	ASN(0.00)[asn:15169, ipnet:2001:4860:4864::/48, country:US];
	TAGGED_RCPT(0.00)[kasan-dev];
	FROM_EQ_ENVFROM(0.00)[];
	FREEMAIL_CC(0.00)[linux-foundation.org,gmail.com,kernel.org,linux.dev,davemloft.net,google.com,redhat.com,linuxfoundation.org,gondor.apana.org.au,cloudflare.com,suse.cz,sipsolutions.net,googlegroups.com,vger.kernel.org,kvack.org,wunner.de,illinois.edu];
	MISSING_XM_UA(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,mail.gmail.com:mid,mail-oa1-x3c.google.com:rdns,mail-oa1-x3c.google.com:helo]
X-Rspamd-Queue-Id: 47C2446DD2
X-Rspamd-Action: no action
X-Rspamd-Server: lfdr

> +#include <linux/kfuzztest.h>
> +
> +static void underflow_on_buffer(char *buf, size_t buflen)
> +{
> +       size_t i;
> +

If buflen is 0, buf is a ZERO_SIZE_PTR.
I think we should allow passing such pointers to test functions, but
each test should then correctly bail out on empty data.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DXG3sGS-_ioH9ThtQf8TCx60vTJZ8Cj33OTfM7FFW62Og%40mail.gmail.com.
