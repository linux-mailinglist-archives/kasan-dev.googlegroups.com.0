Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBTHLVOAAMGQEFTCBGFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33f.google.com (mail-ot1-x33f.google.com [IPv6:2607:f8b0:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 9F8823007EE
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 16:57:01 +0100 (CET)
Received: by mail-ot1-x33f.google.com with SMTP id 94sf656580oti.21
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 07:57:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611331020; cv=pass;
        d=google.com; s=arc-20160816;
        b=SrZcXJRcO3DSLNfqB9wZDygCQm55Em4uT4I8AxXm+4Gxv80DwSLDT99SyVRwJT7sTf
         hIhLYKjGjpUAX8oS14pFkimBliFvyOezBEcThDZdr7i3c4Lk1z9ZGmaViQ0Elu+Gc3UT
         43AljMCeOELxxS7oUt/yHweibwinOQ8zRQ82Z6I+3ZXor+IMpD6RNmxsJPMNuvTMVv1t
         TNpcEuQhmywNc2KMkN1arK/jy+u2KI9GJyxpl3M7lSFMqgT5zr+/9Usj8BwVOOzgn8sU
         XsFFJXABBqwqueU7IilP8MXIQQqJBJJosL1794WD6sbvoU+JSaE3tDo/l6DOmYfyxr1J
         1deg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=WjQmP2wwL+TFiF+tzKw2QIv0wUylTnywn01RDR9Rlto=;
        b=ce84lMIScslTBRO2GE365MQeTcASZK3KjxJmcqD4zkW3EsWyanLgbdvt9AxUMjB//R
         gwYaVkE8UbNkB6dzxZB/YtLhKxaRRK+8BIDrJZXDLc9/MYyCQRi0moVuZcGvD3vtJPVi
         j9e9qciCKyutJBWT+lAcp9/LH8UejMDqza4gwqzJFTyIYfrWhpIMQ+fHE8TIPhnB2Xqp
         OW25VaVp5XT+zu0Qqo4o2D3MwUTadOohjKyrK9wQD8LXUBwrzZvl55BkIQNCXPK7/Cpd
         UQAZa+YQJpR8mpKWSiHNevLOi+UWzNXtQKizl4kMXRSB+ltm1rwIU//XEXNdOERLlqfD
         XC5w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WjQmP2wwL+TFiF+tzKw2QIv0wUylTnywn01RDR9Rlto=;
        b=TdRtLNzHDFvgFccHOIdLTMLuvIj7DliWnOav5AxYv7Y2mi6pUA+W6ER6x4QNOqQlB7
         laStjqJxExVpd7dzdwHoXAwSMv1IAxOHVOPM/gC7d3dfAp60Z6vqW+DbpFdPEJF/I14a
         cuhz81C9T8GolK47BIQBHh9FQUiEoCLgFVlv9J+icv3ZAhdmNZmDCER1lGF3phMnYjMw
         qIXIZhRYX3OZQ5gIIRedbH4hC5MVz2P0o7yw8FhPAZX0Bh0vFf8xkrOAwOU8HNOyoTS1
         7gOID/OIuWua1Fs5bCUHKLv/6C9XyLIpKyd0+dVr7hf+GIQvUxghqJ6hg1S6i/+IYNUf
         hBng==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WjQmP2wwL+TFiF+tzKw2QIv0wUylTnywn01RDR9Rlto=;
        b=UCD0zEPHMhBwrogBVUAWXsEkXRs0rw++uNflF3y6ecF7i/pQ2otn5SKUBE+827UVEa
         MFPKRoiKPDEIRLOt1Zg1RkVkF7KMXh8EXl/kqWqt670boxzOsXzIAD4IOco7Z1kOjIAB
         kr1h8RzpsEh4wIRRYnhugfPXzgPjF7BSziyUBSKNjH0Lc6W0suSSQzbRh/QagFdEEoVi
         B57XFfk/gEkLImDS2YvKXaA9UodS+C007d8Dafx3+lWidINKqY0t/bZz9lyu5F+dOlRk
         JJ/kRx/dDZJ//onGrSGoPLDDJxrrx+aDmjMnempRW53mypqREQnGcfXMausAz7BvCqdp
         7E3w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533EHxNe41AvJD0hNXWtUhlzZ1GawyjDEATBp6WC0fD/XlPySJpE
	2JLke3h1ouWaxXDE1f9nb6k=
X-Google-Smtp-Source: ABdhPJwAaFzEpqo3+HPAnsKk5AeYcYWUT8Bp0YJft0THT9YP0cRZKHBcW4p6RlYYWynQy33LvPtqyg==
X-Received: by 2002:aca:7285:: with SMTP id p127mr3598050oic.143.1611331020588;
        Fri, 22 Jan 2021 07:57:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:3c3:: with SMTP id o3ls1051842oie.1.gmail; Fri, 22
 Jan 2021 07:57:00 -0800 (PST)
X-Received: by 2002:aca:bd46:: with SMTP id n67mr3567277oif.112.1611331020239;
        Fri, 22 Jan 2021 07:57:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611331020; cv=none;
        d=google.com; s=arc-20160816;
        b=lOLzav74yboyZ8F2PfdT151vq7rIZ+ngwargXBVjk0nd7iO4vC65YGdIRnbrH3KWba
         RLdTB+fxF2m5XM2zFunlKQ5oYFHaLmB4bJxiIqQmW+3VivRyLwlHpp8pnx1QQ5E52lTR
         TlYorkVEUtAv40+F2FU6w8QKAXF8HA0hSacEamkQqo9RSWThINo6XhIHskiz2MForYXS
         H4Fkbg4Sc9iZxAA50RXqx4Vogx3RhmjHZL//voMIXIW0pmDZlMxKvUoxp9nU1xhWk2mX
         R6PWzOJDiK/r9Q4N6mHWLJsq9r/Bqt3vlWRSDDBuok4cxeE/+AgOZC3FpnnSQhSKYqzJ
         1ZJA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=pjAOTjE6O0VxMDLlcowTJfJpEWsjCSxNmrRTiiutyZs=;
        b=0o+fiKmBvuStRQFJNQCS6xwPQsvzAZCZRiW2sCeRk+RJNxJzqWZ7znGVtVtUTmjaCT
         /f9AXW3e63vDyETbRMyOdrqFzW9752nSKJl5Gb9Fw7eQCMqpCFpzUtt9SIkCD+S7wvAX
         fEGvjIPhcFq/tYOYEoSWijd092t+HBaungNSfPLHeUovlmdfSMzNWjGGJ+KUcc4wHTmN
         p8oTz7qtVSLR64wD8B2IUYSvNjbImobW6hymmmCv6HBZeM/Vltv5s/i16FLSLFHDdUTK
         PBkTv5pgsW0rm15rPN+6RP9AAO3RK0BYT0W6NBosMKNv2WZ201yp7dXikKooHt7oXemB
         oJAg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id r27si647888oth.2.2021.01.22.07.57.00
        for <kasan-dev@googlegroups.com>;
        Fri, 22 Jan 2021 07:57:00 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 09B041509;
	Fri, 22 Jan 2021 07:57:00 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 407123F719;
	Fri, 22 Jan 2021 07:56:58 -0800 (PST)
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Leon Romanovsky <leonro@mellanox.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	"Paul E . McKenney" <paulmck@kernel.org>,
	Naresh Kamboju <naresh.kamboju@linaro.org>
Subject: [PATCH v4 2/3] kasan: Add explicit preconditions to kasan_report()
Date: Fri, 22 Jan 2021 15:56:41 +0000
Message-Id: <20210122155642.23187-3-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
In-Reply-To: <20210122155642.23187-1-vincenzo.frascino@arm.com>
References: <20210122155642.23187-1-vincenzo.frascino@arm.com>
MIME-Version: 1.0
X-Original-Sender: vincenzo.frascino@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

With the introduction of KASAN_HW_TAGS, kasan_report() accesses the
metadata only when addr_has_metadata() succeeds.

Add a comment to make sure that the preconditions to the function are
explicitly clarified.

Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Leon Romanovsky <leonro@mellanox.com>
Cc: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
 include/linux/kasan.h | 7 +++++++
 1 file changed, 7 insertions(+)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index fe1ae73ff8b5..0aea9e2a2a01 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -333,6 +333,13 @@ static inline void *kasan_reset_tag(const void *addr)
 	return (void *)arch_kasan_reset_tag(addr);
 }
 
+/**
+ * kasan_report - print a report about a bad memory access detected by KASAN
+ * @addr: address of the bad access
+ * @size: size of the bad access
+ * @is_write: whether the bad access is a write or a read
+ * @ip: instruction pointer for the accessibility check or the bad access itself
+ */
 bool kasan_report(unsigned long addr, size_t size,
 		bool is_write, unsigned long ip);
 
-- 
2.30.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210122155642.23187-3-vincenzo.frascino%40arm.com.
