Return-Path: <kasan-dev+bncBAABBOM7RK2QMGQE5XHB76Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3d.google.com (mail-yb1-xb3d.google.com [IPv6:2607:f8b0:4864:20::b3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 2B3AA93C7CE
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Jul 2024 19:47:39 +0200 (CEST)
Received: by mail-yb1-xb3d.google.com with SMTP id 3f1490d57ef6-e0335450936sf2370986276.1
        for <lists+kasan-dev@lfdr.de>; Thu, 25 Jul 2024 10:47:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1721929658; cv=pass;
        d=google.com; s=arc-20160816;
        b=vKVC8EXpaE80yALFQx2CsqBYMdS4NlLBvdiji7nHz4CyeQBVW5FMpDHHdku6Y1xdlH
         T7bRAsmIuuyf7md9SS9apM/nm225yehKBNfGSyWzriJCSI1RYvBpFJkOg9aeWwycghjJ
         D5MOKxp3O9DrFb4aX/tFQyFRNrvHU4LbRny4LaoLUrjTVoSAyaRcy1iEWGL/aSCH4iCM
         0qqo3EiYAPN44xEfxmOVd9gjBsqZPKmknk7LmKDJnPDTvpv9bLmH0o/to9Nascu9UVdT
         bEAFfJvWMQg1gt0pm7ib3f1R0OYDYAvMZrqVWLOm2KlJoLnPAF5hZpDT8MOr8z7h1d4A
         iolw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=J4RGY9DzScqL7p9UubIw184DSmXZVBDIrdN+Q/an9rU=;
        fh=kzAgIt9UGWklPZnTHUYYMha5ShXZFf0vqQV6hE7PNq4=;
        b=L3cakhrI5I5d/n6ai7/8ouLFU6gptnbZUZRC4+WsxA1fC9WFXrygzSAEC+Nl6oFk2T
         5X9Gsm7wZz0RGyn1+REnQUVRHEd1qGs9qJnW7jDzQKq1D0gowXWz45i/N4XKBWmwvznY
         YM3gyXgd45Lw9fQeuf7RS+JpneSZGbNjwBhIWLhhdektriRL5hH9cHxSft90JdTNE/Nx
         HACmx3pvAtibxsBo67zr9xY1qD7h4CrxGWEWN27f6QZGJ8hlYt5WO/eMN4RyeSUKEYef
         NHC1uYHBr+cXdW5rwbzemLlDIiUhz4BhSZsmzwBBFgZeYMVWDCcJ2cmj/+VMaYix6UiE
         Ya7Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of tttturtleruss@hust.edu.cn designates 162.243.161.220 as permitted sender) smtp.mailfrom=tttturtleruss@hust.edu.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1721929658; x=1722534458; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=J4RGY9DzScqL7p9UubIw184DSmXZVBDIrdN+Q/an9rU=;
        b=M6nYr1dpsmbcVrutkdMc7+mEplFcHcjH5u8YWRX0OpQ/tI5cKpPeB9UR02IOcOEL8c
         DI6L5eVZYNQhwpnYkso+GkzKi6oUFYG9jp7GvJa1MTYUx2RyzSRpzGWDykCONOggQ8d3
         OAKOBWLhQs7e8t8j6yv3lm7BbXN60lOeNycE6wVvfaasET1cA2AXWQyRykFO3YtSUb7q
         ZmP57nLUtIuvzRz9tbudwMl9q5LbNTOWEtcBvGbMoj9CyuSOOG9DMwzg/WoBX5ePwaAK
         tJsOsWiDnaJ0mSwWbQfcyx+KnKmMt+dBN2TaFgEmpxEiGtCZdqzdHp1EIW51oaEqWL0v
         u3tA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1721929658; x=1722534458;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=J4RGY9DzScqL7p9UubIw184DSmXZVBDIrdN+Q/an9rU=;
        b=Qfp2opnOMHfwQYHEoLNg/qS9MwDqSwWeYxo5tjpSOP3Onn5stxnk5ScZyhn7UNy43X
         GdUFUdcjy/JAygtT0iFldkZeTATp8YROjaa9lRLqwlu5LL4J/nAKSLGaaifk9l48c7h0
         L0EMtsyxLLHilUxzkZVbDl0mm7XeOGtMwPCreqnI9Lo+451N8h5oepIY5EqkDqP4L/ey
         TDxB4WfQVb9z4ueySpa2ONfaSUwMinrhput0Yyus4z+kV28Nui2dCSySYeusIFdNdy1S
         Y3Nm3y3RKdRm00mfCinSkHwbv/hKBWd0FO7YXgnOV42XYUBKgHT0BjrbN2WkzniPgkld
         cPMg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWIsJhIYF+55lz24BGYYzddkaAZXEUQbf+C6wiJJEhRGRTAWOzppvufVIUiZ86+FdaXTcZWQt68gW+fBOsyK0fvbNYvhs7veA==
X-Gm-Message-State: AOJu0YwoS93YgePQZz8hlL6S2hMW+azQhk7Zh1N30zw2Wv5BHxXfZOwr
	kWDgR2luD29znCot6l4zfsk827E7DEDEKwxGzPHvCSAXOJoIsZZI
X-Google-Smtp-Source: AGHT+IFUKEpe6nz3jQI6rqNASJsatch+R0lj9MgQnoVt9Z0qyPQYRKpIb2FcYbzfyL0OmxM3CvKn9g==
X-Received: by 2002:a05:6902:2b91:b0:e08:6eb9:e889 with SMTP id 3f1490d57ef6-e0b231a0b03mr4759028276.38.1721929657732;
        Thu, 25 Jul 2024 10:47:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:1887:b0:e08:7506:2b74 with SMTP id
 3f1490d57ef6-e0b2212ddf3ls2006165276.0.-pod-prod-04-us; Thu, 25 Jul 2024
 10:47:36 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWed7suL1FSlAqfU7FmJxpUw4i7lwfpDMHZEWyfxgAlQq1KiyxY55MKP0uS8u2ZpT3ktLf0Ox24q0zirpZnhTw3gYCswuMtWqyF+A==
X-Received: by 2002:a05:6902:150f:b0:e08:6761:77c1 with SMTP id 3f1490d57ef6-e0b231a1edbmr4781824276.35.1721929656230;
        Thu, 25 Jul 2024 10:47:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1721929656; cv=none;
        d=google.com; s=arc-20160816;
        b=SW7uwwNS0kU652LJwv8eOAC2hVQ/k3dMQNQ0Gh/AqQ2WETxQp7/pby+ykuixB0PZ0x
         tLbjCOlNa0lo55snAvp38EWW3GJRKcZncmaIMeYGk8zVSqlrBN+1CduE/ZRtz3cACjYF
         YTE01+el0ubsbGyc2J+frHnyhN/w69NmfFDG5Xfyu4UL0K3PWFuviK4N/A40wK81HST5
         wRJ7T6IpMs8P7QBmJjZt+4AFrp/bLY5ThY87yRk0Ugk/Cw7xAv5P3A9mNDGi81jEe01W
         WZqqADF1TXjvDHGcJdp7vBM9JunHajbDtKJEsG3KY3M2pTqybTOwuE1vLCCDxERSios2
         6VtQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=9zv+BHiFC8XU4hn3FzlGPYdd/Qq/1Hhdeor8Ps4GoKc=;
        fh=JszYmUkwEfqYpzoAdjSiJznJsAv+/jUIr6W/ZQ6q8dw=;
        b=DMJaEt/+boEdqomgW0mNtfyV3ptSWm9J9ZIup1sDgQibAyBKC5cXpFzVNY2dYJFcR8
         Lb0qiVWsjyuogzzKh8t+yWcx2UqmWsXVe6NkvGwGQIDBbsQLBhtUBk6a0nx/aeAtY2ek
         MPFIn7Dj58NIt+EIcNvmxARj8cYO94Php2qm0wVe1fGmfUczsvOYOPVKIb2zUxPqESOF
         RdRHviyejC5XtAhXYW17ZFY37TlNN40PDyzU2Xtyv+8Ned54FfohqxA8FgiLN9s0fXfm
         7KC5t8zkB6UQBHZUBcpe76nxvEVk8/e6t5SlIXGUfznjSeC8Hs++8UfcCc3OzLESyhAt
         7gtQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of tttturtleruss@hust.edu.cn designates 162.243.161.220 as permitted sender) smtp.mailfrom=tttturtleruss@hust.edu.cn
Received: from zg8tmtyylji0my4xnjeumjiw.icoremail.net (zg8tmtyylji0my4xnjeumjiw.icoremail.net. [162.243.161.220])
        by gmr-mx.google.com with ESMTP id 3f1490d57ef6-e0b2aff712dsi82925276.3.2024.07.25.10.47.35;
        Thu, 25 Jul 2024 10:47:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of tttturtleruss@hust.edu.cn designates 162.243.161.220 as permitted sender) client-ip=162.243.161.220;
Received: from hust.edu.cn (unknown [172.16.0.50])
	by app2 (Coremail) with SMTP id HwEQrAAXwBSGj6JmH2lSAA--.20365S2;
	Fri, 26 Jul 2024 01:46:46 +0800 (CST)
Received: from russ.tail3da2e.ts.net (unknown [10.12.177.116])
	by gateway (Coremail) with SMTP id _____wA3oHB5j6JmEy1vAA--.22887S2;
	Fri, 26 Jul 2024 01:46:45 +0800 (CST)
From: Haoyang Liu <tttturtleruss@hust.edu.cn>
To: Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Jonathan Corbet <corbet@lwn.net>
Cc: hust-os-kernel-patches@googlegroups.com,
	Haoyang Liu <tttturtleruss@hust.edu.cn>,
	kasan-dev@googlegroups.com,
	linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH] docs: update dev-tools/kcsan.rst url about KTSAN
Date: Fri, 26 Jul 2024 01:46:31 +0800
Message-Id: <20240725174632.23803-1-tttturtleruss@hust.edu.cn>
X-Mailer: git-send-email 2.25.1
MIME-Version: 1.0
X-CM-TRANSID: HwEQrAAXwBSGj6JmH2lSAA--.20365S2
X-Coremail-Antispam: 1UD129KBjvdXoW7GFy5Cr1fGw1xur4kCry8Xwb_yoWkXrXE9F
	WfXFs3J3s5JFyvgrnYkrsrWr47ua1rJrykAr4qkrZ8Gasay3ZxXF9YyrW5uF1UZ3y7uF9x
	Ar4avrWayw1xCjkaLaAFLSUrUUUUjb8apTn2vfkv8UJUUUU8Yxn0WfASr-VFAUDa7-sFnT
	9fnUUIcSsGvfJTRUUUbaxYjsxI4VWxJwAYFVCjjxCrM7CY07I20VC2zVCF04k26cxKx2IY
	s7xG6rWj6s0DM28lY4IEw2IIxxk0rwA2F7IY1VAKz4vEj48ve4kI8wA2z4x0Y4vE2Ix0cI
	8IcVAFwI0_Gr0_Xr1l84ACjcxK6xIIjxv20xvEc7CjxVAFwI0_Gr0_Cr1l84ACjcxK6I8E
	87Iv67AKxVW8Jr0_Cr1UM28EF7xvwVC2z280aVCY1x0267AKxVW8Jr0_Cr1UM2AIxVAIcx
	kEcVAq07x20xvEncxIr21l57IF6xkI12xvs2x26I8E6xACxx1l5I8CrVACY4xI64kE6c02
	F40Ex7xfMcIj64x0Y40En7xvr7AKxVW8Jr0_Cr1UMcIj6x8ErcxFaVAv8VW8uFyUJr1UMc
	Ij6xkF7I0En7xvr7AKxVW8Jr0_Cr1UMcvjeVCFs4IE7xkEbVWUJVW8JwACjcxG0xvY0x0E
	wIxGrwCF04k20xvY0x0EwIxGrwCF04k20xvE74AGY7Cv6cx26r4fZr1UJr1l4I8I3I0E4I
	kC6x0Yz7v_Jr0_Gr1lx2IqxVAqx4xG67AKxVWUJVWUGwC20s026x8GjcxK67AKxVWUGVWU
	WwC2zVAF1VAY17CE14v26r1q6r43MIIYrxkI7VAKI48JMIIF0xvE2Ix0cI8IcVAFwI0_Jr
	0_JF4lIxAIcVC0I7IYx2IY6xkF7I0E14v26r1j6r4UMIIF0xvE42xK8VAvwI8IcIk0rVWU
	JVWUCwCI42IY6I8E87Iv67AKxVWUJVW8JwCI42IY6I8E87Iv6xkF7I0E14v26r1j6r4UYx
	BIdaVFxhVjvjDU0xZFpf9x07jVtC7UUUUU=
X-CM-SenderInfo: rxsqjiqrssiko6kx23oohg3hdfq/1tbiAQsIAmagdi8lywAHs2
X-Original-Sender: tttturtleruss@hust.edu.cn
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of tttturtleruss@hust.edu.cn designates 162.243.161.220
 as permitted sender) smtp.mailfrom=tttturtleruss@hust.edu.cn
Content-Type: text/plain; charset="UTF-8"
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

The KTSAN doc has moved to
https://github.com/google/kernel-sanitizers/blob/master/KTSAN.md.
Update the url in kcsan.rst accordingly.

Signed-off-by: Haoyang Liu <tttturtleruss@hust.edu.cn>
---
 Documentation/dev-tools/kcsan.rst | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/Documentation/dev-tools/kcsan.rst b/Documentation/dev-tools/kcsan.rst
index 02143f060b22..d81c42d1063e 100644
--- a/Documentation/dev-tools/kcsan.rst
+++ b/Documentation/dev-tools/kcsan.rst
@@ -361,7 +361,8 @@ Alternatives Considered
 -----------------------
 
 An alternative data race detection approach for the kernel can be found in the
-`Kernel Thread Sanitizer (KTSAN) <https://github.com/google/ktsan/wiki>`_.
+`Kernel Thread Sanitizer (KTSAN)
+<https://github.com/google/kernel-sanitizers/blob/master/KTSAN.md>`_.
 KTSAN is a happens-before data race detector, which explicitly establishes the
 happens-before order between memory operations, which can then be used to
 determine data races as defined in `Data Races`_.
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240725174632.23803-1-tttturtleruss%40hust.edu.cn.
