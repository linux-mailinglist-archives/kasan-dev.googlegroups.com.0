Return-Path: <kasan-dev+bncBCV5TUXXRUIBBC4Y4P3AKGQE5ALZGSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id E799B1EE261
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Jun 2020 12:25:15 +0200 (CEST)
Received: by mail-wm1-x340.google.com with SMTP id 11sf1644737wmj.6
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Jun 2020 03:25:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591266315; cv=pass;
        d=google.com; s=arc-20160816;
        b=LRr/4oznYKoz9ukQ/o+eCqSuC31ePeEDvX386JHWjbHuZfBmBmFdxb9XOiVqDwcafy
         g2PFPcCzGplNuTEMm+MUfq85O7sUq8I+/EL99hgur2QgU7+5MkH1TRe3Ei0fhfcb1cTy
         uhsqSrJz6tL//CK8IimF7nl+8aa02NJWBGcnaKhOAzLsXXihxeraJt1+se7lFZNZY7wL
         /Ztbw/jxD7GSniChUPF8tmkQPMsLMbEsX3xQ79x5S1gfVI13dO7HtCbdTg3Y8vzbE0VC
         u310cPKenNODcQIPBYqP2f1bJ+Q1ivF47qPnc5ALVa+K+ZIpSpHM9psA6oZDfIZXhDyd
         1T2w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:cc:to:from:date:user-agent
         :message-id:mime-version:sender:dkim-signature;
        bh=u5ZfBEjVyGj2mT8c2zsTtWu3/AQfkfsarYB1LOVq6kQ=;
        b=SrT7towHwAao2M/ZMre58K6DWCjUlb12lFPqXohM8N27cTtOsA9jD0C4sdzMn3qmaC
         PNgvBYasFbZUNmh/Fpnl2EBpP3TREELSZLtKkAN6Kti+HyuNBWplJrH43GKkx2grdT8H
         LvfqFSdtoNRaMBX+SKoZtBvLk1xqEsnE902CX9na1iE06zUDgP/2JRr/e1Pr/c/vLy/U
         B60iMYJrb9kMYoEEjNKqdz5Kz7jtesgK0A7cU4UuvRuuIc+ugANGWxXYtXITihZpn7dV
         9bCrtxf346EDlx7kJHDDYJizkGmzGK19bGG1HVLzyarIXUYx2OOPznPmXIlCPfhE+ODq
         4H4w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=E1ja0y8T;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:message-id:user-agent:date:from:to:cc:subject
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=u5ZfBEjVyGj2mT8c2zsTtWu3/AQfkfsarYB1LOVq6kQ=;
        b=i6mqGuSH7S8qox7SLWiMkd4+Xhy3kn2UuXPnAneYrsX5XhNcv+77tnYuSl4CQmsfa7
         8dZVjNCKGnKed8+BnFTYFsDfkT+ufwSbL9j6DDRDWzQDytrV8CzTewwPdaDAREo2c/ca
         K7UEYkQtjmMKQRXfIdmhMIEP8/wHcL/cH/H+v//Y5XJsbgKndDFQzHS5AswRaOwl3ptD
         T5alveB5DrgvU4DZxEABqUaPQxYqxusjDmDxspyG5jSoJrwtuQbAZvGNEfyUv7mdrGY1
         v6LNc3mKawgJfzYUL+WbKs1OqkeLpSb/UvZVJEob5e7TeZsW+pjE+acxG4E35BHgsBQ4
         es4Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:message-id:user-agent:date
         :from:to:cc:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=u5ZfBEjVyGj2mT8c2zsTtWu3/AQfkfsarYB1LOVq6kQ=;
        b=dqGhnnVq+CyQBIVWTt2AgsW6bpFSEYmvoOpwmtj67n3mZoYmdm8fxbeN6dSLNfGNrZ
         kdqpS/KUvmsv3capJSkQnJnseujes6oIgTHrrndn/1he6zmSUbxw0XdHAlCnwVw/OrhY
         4d2dNEB6PXM1/S5a5Qdg07Vd0VDcWFeeYt1O5ksgykPI0fZJiX9cG1FMsZ1rXZr3JNBu
         ttpzsWIfbdRLmK/mJ5yVyZVlvOitNIx3ayu8okeS4i8NRlLurqb/+9k7ki7D4mm1UwmB
         GxNB8hAhNibnlFHV498pn0vy0KMWiYGagykCNixoYJ3cr7uZsKF1Gav7E+e7B9oi8Uuu
         fPqw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530fun5RrgqPZeLhabd6cSAJ9H7c1u2n7B0B5EPv9YClASvXTkr+
	quJpRDD9iW7tggecG2u9VX0=
X-Google-Smtp-Source: ABdhPJxClH97c3F7fsSb4gpKVeI0z+UijNppxPykWHWVJHMsHKfKNjlkixlGk6vs+jLH65WTQXlSGQ==
X-Received: by 2002:a1c:9c85:: with SMTP id f127mr3438945wme.79.1591266315650;
        Thu, 04 Jun 2020 03:25:15 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c959:: with SMTP id i25ls2556597wml.2.gmail; Thu, 04 Jun
 2020 03:25:15 -0700 (PDT)
X-Received: by 2002:a1c:998c:: with SMTP id b134mr3573770wme.78.1591266315178;
        Thu, 04 Jun 2020 03:25:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591266315; cv=none;
        d=google.com; s=arc-20160816;
        b=ESBUfAjJ6N+yZk7AjdHEsU+mzLgpV9YVNl9e/UfEGF+FS/iVlUMmJihK2UJekz2JXo
         VFFAuXKe84gkNTlSP5PU4QWxbK3Hxd5gRO8EpZxSjlESM0w1h2YbckB0Vf4ix6g5P0CU
         /mfHZ8HLxgxq3iFnIUAWKS4BPZPH4FcOSJeReLcntKPZpJ9gWxFeXib/Sz25ORDqAD4h
         XXL5mQCakqhS8clQVQ+sKO1hHu9wnQUfa2vbPvMvx66Y3OpnsalTjEqMC635Re/jODzt
         7iF2WCST9NL9rxJFPNhlfPPoJquVcRSdXm04P55dqq5QshynnPQPJ1tY9bevsq5nSjmX
         QEiw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:cc:to:from:date:user-agent:message-id:dkim-signature;
        bh=mArLRZM2rhn2tsk3MmdLOGj2f8ZPcyzKUmaO03kjRtI=;
        b=LF4Q621dus5xHFE4wuuv+FiK99KWmM5hv+hkmbomfOHCgWEVJeBNgelXfiBzPQEPO8
         L2MKdnffZ74YnnxPA53CHC9t01fb+56pI+JI233/ZyGd40Jrh2HEX75QyK0Cs196MJBI
         UDLFwatNoVW4TaCPT7sRDSKfXrWjhvyW14NNsBmC1Qs1UDBaNVkDw0hYYLkl7K9/qoV0
         6ZWVsImJKRKV3oLtQ37GPyG+/4V5/6vFaH5H5Uk4qr4eL7JYUcdIT00aGn0M++N47lNU
         DQ6YF8AYVNJhv+6HZsdCBPvAeLNNcmSYVHyhDVvK/UWASKHKVF1iOBCf/vzOYaDfqSGV
         qRlA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=E1ja0y8T;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from merlin.infradead.org (merlin.infradead.org. [2001:8b0:10b:1231::1])
        by gmr-mx.google.com with ESMTPS id i13si257586wrq.1.2020.06.04.03.25.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 04 Jun 2020 03:25:15 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) client-ip=2001:8b0:10b:1231::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by merlin.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jgn3d-0003ta-4b; Thu, 04 Jun 2020 10:25:09 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id EBD5D304D28;
	Thu,  4 Jun 2020 12:25:07 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id D312B20C23590; Thu,  4 Jun 2020 12:25:07 +0200 (CEST)
Message-ID: <20200604102241.466509982@infradead.org>
User-Agent: quilt/0.66
Date: Thu, 04 Jun 2020 12:22:41 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: tglx@linutronix.de
Cc: x86@kernel.org,
 elver@google.com,
 paulmck@kernel.org,
 kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org,
 peterz@infradead.org,
 will@kernel.org,
 dvyukov@google.com,
 glider@google.com,
 andreyknvl@google.com
Subject: [PATCH 0/8] x86/entry: KCSAN/KASAN/UBSAN vs noinstr
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=merlin.20170209 header.b=E1ja0y8T;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

Hai,

Here's the remaining few patches to make KCSAN/KASAN and UBSAN work with noinstr.


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200604102241.466509982%40infradead.org.
