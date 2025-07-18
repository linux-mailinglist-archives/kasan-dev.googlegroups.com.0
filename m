Return-Path: <kasan-dev+bncBDAOJ6534YNBBYEA5DBQMGQE3YDN76A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 72A05B09D5F
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Jul 2025 10:05:55 +0200 (CEST)
Received: by mail-wm1-x33e.google.com with SMTP id 5b1f17b1804b1-4560f28b2b1sf6181145e9.2
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Jul 2025 01:05:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752825955; cv=pass;
        d=google.com; s=arc-20240605;
        b=AUdVmHJKY2Xt6r5bSmLUWO0fJyQfldvIBE7I5+RFnjajnGzAm4kHv/xcBpIRVz9e36
         f5fsfekL9QdiGyJczrz9/Je2LP4ePPGaN3P9T20qAV4nf6VU1ytcIPGbCdlovK+4pWj+
         3UeDJGJJbX0uQCTL+ffcqxQT+CdB1O7zambkwWe2AblA2W85su1ivVOrnGBEoKhPWm2G
         FdgoyQ872YVQ6/lia9dAGXFJWpZsbS5FNuEW+1sLZfB51JGju86e+6OYDOlHdoaxx7ta
         C2eRVF1IUydMR/xX6tfDGZPQU2QMx6a2Uk/KCyf9v9X3tI3h7G1cAp9IXR8EWTjzNivd
         l5tA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=6B8uexXStC892AV1pphED8VMbFXooUY05OVJvJ8UKow=;
        fh=rFavTLf8UPYJn2/ATLN2rjgYWCFfPwchhvmKsEWEwN4=;
        b=XqWDx5sDSa9jk/a00q++aORSyqXI0OtwHRddv5VYcuKs6/GyDiuBGXGNn6TaQK0SdW
         0AmJsf4Qsii/BgicUyIuskUoZdg0OaIBdAGkpkiawKyAki5b5t+7U5FTR/C1gypH4iME
         CgATpjhKAG01zQSINQLVgq5DCfZy4JzRZ3iIDFmHTB/lUkBLu8Np7OjfVXlFf3BoyFav
         CgDXkp2j/qMFCmZLH52KtWWiwIwvl+YMaDpMVwf1wcQDYcMAGMxT8zw+sv3lyOBQsAtM
         afu4StwYDYz4OZQF53cBPcQoabPL8s7JmbgCk+pU1vymIAtHszcbgHzf08R0yNQFrp7H
         aoTA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=cnsEDjtY;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::22b as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752825955; x=1753430755; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=6B8uexXStC892AV1pphED8VMbFXooUY05OVJvJ8UKow=;
        b=oJ+mu7MUGHGw14ul1vENxI3UXgI3mrl5XOPYvyM9fQCYEKsQS7Iiibkz+MIgT8DIpG
         L2WQXTC0ygam+pAxFf/7vBJ2I+AGcVaP1gVHLvL1KcL5o9kB7zyw5XkuQq3dC6iDX2bL
         ZHaGyzoSy7+RgwFSb5VIQ6kNUEMtv0R+kuGqCusdjcaIxmdqijgGeTw86Lm/Tkt5SpJj
         74WvctvbFwPSsan+wYdSnW7FswIfoFZlvivXBX/4Mg9FuAop8wsqxlgW2kU4dxCuQR2w
         L76GW61NWt/r6UhRTMzjeL+DScLY7ro+FQHmjPjGFChiJcjBT47fjRWHz2f+TiafRtWs
         T9Ww==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1752825955; x=1753430755; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=6B8uexXStC892AV1pphED8VMbFXooUY05OVJvJ8UKow=;
        b=lWRclZDDfPUkIpp0srooqviijketdJ8P3lHNcuIjX8frpWncCGmZypbZXwrocwSS17
         Ozj3lXPRXyQzh7AwNgRntaR155zuVLeBRVmDfGeIU1Cwh8CWrdNNe7HHLb9befL34r0q
         nCYaSfdymtD5O1IQ8UxcW3iCVa3+K28BiFFhvU15aMx0uWLQeZrtEFVbfTk91GPDo3LJ
         NTpJoLN0QiR+5JrQJyklGnDUloYIQ3uKkLuCZXRVU3SEH3jHcsakXSZX74hcha9xYcRJ
         mitLdk+8tVduYDNSo5YhCTlDMqMTDY++YyWXj2LQhQbW5ZkAi4u6zZSeJZrOxm81AAk6
         XyQA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752825955; x=1753430755;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=6B8uexXStC892AV1pphED8VMbFXooUY05OVJvJ8UKow=;
        b=BoT1ZL7tLeuQt5BNa2HXecs/5OZQXAKCMZ6TTmOYQNS4Vb+u2f1HHfw7+Ut7z7jEu8
         3WkE/u/Y6s/xGkPBtJf9d7Zpv7HRAke35LenHqa+G+3PO79x9iYP70x581F1aV8b73LM
         5HGkw6Nw1egD18p6ia2iTvoOzqutKXykho0PDMVLekXWUtLENSGhtCzph9OedP1CyAIn
         1oJvKuieQvI8qn/zDDtl7G9noVHqt8p9lAKcM77Zefehoo7KqWDLJBxnB/RGiUnuMtmI
         zou1em6ZnFqLesCbmDaZVD9Vezew6Eol780Lk6jdjhLMCNiktTSXmXV2yn3/Bdnp9q4k
         8azQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW6piTcKsH0Lly4CPjfZnKQfOM8gPmZXiETQS8E5XAQFCarJ+9UhC/7AhlFTdtdWnbwj2e1AQ==@lfdr.de
X-Gm-Message-State: AOJu0YwkUHkxxZn5c8t8XCcqNMobww4of0rhSStVP2C+jn7bB/XjLipK
	HNkk4xws8ls75lwNWjlxqoij0UvakPY28L/Vtm17KJw/LjgKNBgaR/1u
X-Google-Smtp-Source: AGHT+IFEecHSxnCqYkYKv44MBYcHh1rjEM0u/1aSqI/+rNemrKSllC+XFetZQK1sXzn9LG0iqfrdEg==
X-Received: by 2002:a05:600c:1f13:b0:43c:fbba:41ba with SMTP id 5b1f17b1804b1-456327bbf81mr58161075e9.28.1752825954400;
        Fri, 18 Jul 2025 01:05:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcYAZ34IKG34vuYUbjLQEU2ztsTu7Lxoyt4o0jG4iYOng==
Received: by 2002:a05:600c:3b8e:b0:456:11a9:85e7 with SMTP id
 5b1f17b1804b1-4563409f501ls11099275e9.1.-pod-prod-01-eu; Fri, 18 Jul 2025
 01:05:50 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVFfwRSOiQYmCGxxQiebCc4T2iilPGC9vAVMSWxy5Ks6pFcOy/s79+eMBJ5Uk87Z+8gSt+tjWCM5jc=@googlegroups.com
X-Received: by 2002:a05:6000:144d:b0:3a4:cfbf:51a0 with SMTP id ffacd0b85a97d-3b60dd6dca7mr8202738f8f.21.1752825950576;
        Fri, 18 Jul 2025 01:05:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752825950; cv=none;
        d=google.com; s=arc-20240605;
        b=j+mOpb2wlP6k36F4XadzqDedb/XkNaIyHSiQSeb4oNH4ghjzetGoAV4IFTAh8oa1uO
         QOO3FandJn2IbGCi+PNr1KTlMG+GexQ0IBhUjYtNbZ4y3v34o9U/Y2fEeRNHJfPv33oc
         htJXQSoBKU8gVe/4/YTutNjcnmcrofUuRlE7LajG6C7MyDH+hcfznuS+NfqY3M3PYhfR
         wAC5jYyCH8Tzrx89y+7dhp0XLk3gxZ/29f8l2pw+i8ZwSNOQX3vWo9rjiElp3BwiGrct
         t/1Po8gxwhi6q4a9ob5DcNOheH7T7q1NBIvU5smzgEhcP33XnmPetMr8XN8bOtdziHsJ
         Q7Jg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=mE5OlSABnLgWhYl6SAq4PjOG8cGD+M3libfM2kaqTAg=;
        fh=GexxsqtfgqKqHiLt7b94Bi6/FlnRuYZ4aUrxXVYKUyY=;
        b=VrSaW+5NMPlZ3ogRM6vHTZCSYqpgCpc6UIqgalVqyVUjOyBU1XMRaNRh418YZTKV6o
         lVB4vxRwdhIkMI34cG5HmFKxxoH60KeVBp/iit2yCXfQ9L97wim9AAf/iMB9F8rK5olU
         +/4P+F1GqtEMP6IyBqXVhYgugUSxgpZ3UGip4bqaTHGUWshSsKQG4LLMu1+HsZa8SkJo
         ihiGbUEDRX2Ky6LFsF84Me8jdHuZggx9ImMs+wVW33eqo+fTa45WTNnm2H7jiMlQKN4S
         eqX7LcYLUnasZPavPqlZB2B8ecDAmEuH+/lWByTdMG3spmo9XouX1jETBnsvFxl0Mdeg
         NrrA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=cnsEDjtY;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::22b as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x22b.google.com (mail-lj1-x22b.google.com. [2a00:1450:4864:20::22b])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3b61ca42ddbsi21827f8f.4.2025.07.18.01.05.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 18 Jul 2025 01:05:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::22b as permitted sender) client-ip=2a00:1450:4864:20::22b;
Received: by mail-lj1-x22b.google.com with SMTP id 38308e7fff4ca-32b7cf56cacso16957901fa.1
        for <kasan-dev@googlegroups.com>; Fri, 18 Jul 2025 01:05:50 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXw8ixKKaiPNNy9lWOKbt9+cR5bEJJK3QcZssGzJVybSnwPIovGL9MnaR9HrybU0iFGJ8/hndUbpYc=@googlegroups.com
X-Gm-Gg: ASbGncuoKchyUuksAH4FKERmX5bCRwguvDtNLOMKKsbFBsC9vXdYtqUeZXLYvFbZCLC
	B6e0RBsLPzj2GE+VpLR0aQTHZWJSZMWdTVo7kkONAigIjAGQgh74uMfZq8iqhpNicsyXOLiPsYn
	wGhUBvEemc91vIGxMQpL8yo6DzqUKM3h7rFqH2cgiOzo1j6bj0UKyi/t/xnzFrU/hiYwkId70iO
	JMSlsI=
X-Received: by 2002:a2e:80d4:0:b0:32b:755e:6cd7 with SMTP id
 38308e7fff4ca-3308e56e179mr28488571fa.32.1752825949700; Fri, 18 Jul 2025
 01:05:49 -0700 (PDT)
MIME-Version: 1.0
References: <20250717142732.292822-1-snovitoll@gmail.com> <20250717142732.292822-2-snovitoll@gmail.com>
 <20250717151048.bb6124bea54a31cd2b41faaf@linux-foundation.org>
In-Reply-To: <20250717151048.bb6124bea54a31cd2b41faaf@linux-foundation.org>
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Date: Fri, 18 Jul 2025 13:05:32 +0500
X-Gm-Features: Ac12FXz9YqNA1eFVik-g2DCaFm9kQISkxpcsj01QS2Zo6EkvjPY09aiUDIQMxqs
Message-ID: <CACzwLxgyd9yd3ah=LK93Bn7SwAy7H1Hhi=ncFzZYUs+6YGEqvg@mail.gmail.com>
Subject: Re: [PATCH v3 01/12] lib/kasan: introduce CONFIG_ARCH_DEFER_KASAN option
To: Andrew Morton <akpm@linux-foundation.org>
Cc: hca@linux.ibm.com, christophe.leroy@csgroup.eu, andreyknvl@gmail.com, 
	agordeev@linux.ibm.com, ryabinin.a.a@gmail.com, glider@google.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	loongarch@lists.linux.dev, linuxppc-dev@lists.ozlabs.org, 
	linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org, 
	linux-um@lists.infradead.org, linux-mm@kvack.org, 
	Peter Zijlstra <peterz@infradead.org>, Johannes Berg <johannes@sipsolutions.net>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=cnsEDjtY;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::22b
 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Fri, Jul 18, 2025 at 3:10=E2=80=AFAM Andrew Morton <akpm@linux-foundatio=
n.org> wrote:
>
> On Thu, 17 Jul 2025 19:27:21 +0500 Sabyrzhan Tasbolatov <snovitoll@gmail.=
com> wrote:
>
> > Introduce CONFIG_ARCH_DEFER_KASAN to identify architectures that need
> > to defer KASAN initialization until shadow memory is properly set up.
> >
> > Some architectures (like PowerPC with radix MMU) need to set up their
> > shadow memory mappings before KASAN can be safely enabled, while others
> > (like s390, x86, arm) can enable KASAN much earlier or even from the
> > beginning.
> >
> > This option allows us to:
> > 1. Use static keys only where needed (avoiding overhead)
> > 2. Use compile-time constants for arch that don't need runtime checks
> > 3. Maintain optimal performance for both scenarios
> >
> > Architectures that need deferred KASAN should select this option.
> > Architectures that can enable KASAN early will get compile-time
> > optimizations instead of runtime checks.
>
> Looks nice and appears quite mature.  I'm reluctant to add it to mm.git
> during -rc6, especially given the lack of formal review and ack tags.
>
> But but but, that's what the mm-new branch is for.  I guess I'll add it
> to get some additional exposure, but whether I'll advance it into
> mm-unstable/linux-next for this cycle is unclear.
>
> What do you (and others) think?

Thanks for the positive feedback!
Adding it to mm-new for additional exposure would be great.
Given the complexity of this cross-architecture change,
I think of taking the conservative approach of:
1. mm-new branch for exposure and review collection
2. Advancing to mm-unstable/linux-next only after we get proper acks from
    KASAN maintainers/reviewers, at least.

The series has been thoroughly tested by me - compiled all affected arch an=
d
ran QEMU on arm64, x86 with KUnits.

+ Forgot to add in CC Johannes Berg, Peter Zijlstra who commented in v1.
https://lore.kernel.org/all/20250625095224.118679-1-snovitoll@gmail.com/

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ACzwLxgyd9yd3ah%3DLK93Bn7SwAy7H1Hhi%3DncFzZYUs%2B6YGEqvg%40mail.gmail.com.
