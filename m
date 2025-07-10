Return-Path: <kasan-dev+bncBAABBIGUXTBQMGQE5W232BA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 9EF80AFF70E
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Jul 2025 04:49:07 +0200 (CEST)
Received: by mail-pl1-x63b.google.com with SMTP id d9443c01a7336-23692793178sf4792085ad.0
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Jul 2025 19:49:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752115746; cv=pass;
        d=google.com; s=arc-20240605;
        b=bPNqsmimU8tRn/5/5f1ZrLWYaK54HlVweTsToXO8iWgMS9hWWzZ1qaplwQnCjBsvDG
         5Qr6ukAa2eE30p/zgzPXCARVk8xwwgm5U1u36XAoWUzpaauy2+I1iGneDSVvreljjQne
         qoTC/v50+0Rzi/g0KgC/HNGN2f5Ok/dPeqap12yXebzr6QRn5UMUmIz8Pa4ZrracMvDw
         5CPgKex+jYmQGsqqlIPQO+NhIkuLef5cxNGI12I6eD2U0YCvpLTAGYz2bV6zMFWrmHJJ
         F49cwjLF/cA8dKUSWwVHqap0wOJ+YfgoBFbV/XxIyBE/cra3njWf4qHpLUFn4m6paphP
         zJyQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=eZKhSJ3ev3v2ONi3tlhc/lv/6k/SjuWMbD/cVCSd9f8=;
        fh=0pcbEjliYfqGibSPDCyse3vrbsOsWVGVxsQ/LbqeZZ8=;
        b=aaOfqvRxrs3gbH/NlP92Ns0j/oU0ruxnaKJjZ3FVp1tAuF/8Jtabr28BO69FO+FOSr
         fxQcU5WmkhFFh7SkpUDepTmCusEbHKUbXmicN3wGdbSDZgtTcUqCp8/lG9d0SSj9Wl3y
         roliLD6K/G+C8u4YWNGITgqfcQP8Rg23w7GPqvgxUpPPmkd1844HnmhqK0ZaJ+0z9opK
         KCaFFYlR2VpKF6xClVek9tHHkg29iPT2Wi6Gxvw8ts2S3eYDfK5OAUHRXfLFTEUzGM00
         aa4PXUmjzzE8CmXvsMHYijSMOrVhn6r/m56GYqgfatvybN3zctVJH5pHCHjHuUnanL6t
         zDHw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=L3XJL0VW;
       spf=pass (google.com: domain of alx@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752115746; x=1752720546; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=eZKhSJ3ev3v2ONi3tlhc/lv/6k/SjuWMbD/cVCSd9f8=;
        b=fMAPNzt3qQ35y340ZzIZJHlOkFEBV/Bgab7i9tlP3X0XOl4dgNzGbx6+UTRP7X+bPv
         IerJLW9h5xqOxorG8wpTufWyQj08RC5PssTMUa0++XAm26YZyzrqtEUreToSj89DDjWN
         o7Rlg7NyZisqLTVcTcuD8ZYnYrq1EtacynqvZMEa/B0M9EB1+tlqlnt1SOjYonhxG5lS
         xemW0j81lOtSDs226rEmO82FEe9pCif+5JJpqPeko/EHU2V63AUphiPBsQRR2ZK/f9QY
         3Apc15j0BmmfBg3Ag91RPh0dmP5DRqs2zTizlICGpzuueK4oenS9coa+neBFrAiMfPzc
         b8/g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752115746; x=1752720546;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=eZKhSJ3ev3v2ONi3tlhc/lv/6k/SjuWMbD/cVCSd9f8=;
        b=bX6yAGEVaMPcDGYp+HBWQ99yBS41BN5eEh8c9kfFpBwRPh/yWpYq22ukOtH9lw/2lP
         g5x0veArLPaAjVlyh4Xw7W4HUY7Cfy9W9oXjxYE0sRzUNwLxySrnEKvszCZ5Z+VlGg3Y
         UZ1CX1B2YTE7zsa8KvlGs+TP935j1NtUWgFe2dQ1+wGH64bptU9SuA7FhbqSjUwKnkpD
         S/nJu09xBvrsDFsPQ8yEO3vVR+WxyyFZ49NJ1MJ8Y22MrBnfWtgMVG5qHYPwbsZY0dwa
         qsLoLB9WR+6EHbGI8EhPxpYuEpogoYbob0XFeCj4gH6muURMClCFv4bDE9xh2iRpXRrv
         CVWw==
X-Forwarded-Encrypted: i=2; AJvYcCX365TEw12VDPrl/i7OEOrkj/+WedC5128ZuWlqJpUBHiQega+M7Hy8VyVbIqOsWURuO5RetA==@lfdr.de
X-Gm-Message-State: AOJu0YxbwySyS9JxQLD02sP21RcVzPzJ4CHNq74KrFwgK0w7RqhpcLXx
	WGqbY3PCx9hJMHVm60Iovv/ZswZxk5hMsEJYc8FD+G1DvhBYtLhl5Maz
X-Google-Smtp-Source: AGHT+IGlT3LKqcXEx6Ihx9c25d/nGCiLbS3YvtblhpC4w12EdOSXmqrUWf9GZca1JvdzIxeM2rXd6g==
X-Received: by 2002:a17:903:285:b0:234:986c:66f9 with SMTP id d9443c01a7336-23de2471cb1mr34165255ad.22.1752115744917;
        Wed, 09 Jul 2025 19:49:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdBHiZM0wIQMdVd5DD2y8xi/+S6D+YIoUdQGhczbcjJvg==
Received: by 2002:a17:903:2055:b0:234:9fce:56ab with SMTP id
 d9443c01a7336-23de2dfc22dls2846055ad.1.-pod-prod-04-us; Wed, 09 Jul 2025
 19:49:04 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUjIsAYVaAHpSCO3qdjQRbvvhuhrAdBEUzkr2fWaOksOTQTW/kXwiSbt7bbeg8Az9gvBRZcKTMdDRc=@googlegroups.com
X-Received: by 2002:a17:902:d2c5:b0:234:9068:ed99 with SMTP id d9443c01a7336-23de24d94famr39040545ad.24.1752115743733;
        Wed, 09 Jul 2025 19:49:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752115743; cv=none;
        d=google.com; s=arc-20240605;
        b=S3UFD1Bts+WpY5j8VWqK6JBr+XkhWpWMx04yz3vAbgTiWQCsAvG/8m+qJd8eYjgdSy
         4qtqWMCRd+NcFIb/DhEtR09GlpZFxH5bYABXaUA110/WhcLpQFPI0FE8/BKhozVyeFRH
         osGg5HphVkmqQDmt4p9fnvnq+eQNlfiB3SBzBeYJ014TKsMkelcIpxxhjRJae1/04zjM
         P3AFPp88N4ewAxmdIOCxBH1kfxkrjfu9PbnGrD4RW+SGqK/kgRewA0HJ8Syl7QxOVdvf
         LCUWynaGGu/0mhs3nFwJdecPTGssBDgRWWZiOlKmU/e3bobR70M/kUTV4KZrQl5eVGdo
         H/yA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=zREMmcxE/LRZo3kxFplfxyWUi37f4QYm5LAPi+hG0b0=;
        fh=n7kMCQJrry/6/0/v2g7rS6NiIhn1Yg+3PC4f8tlptsI=;
        b=SEun1WzQ0PHhRhk+ZApORpoIN0yDjUoPCIwNjMzjO0s/5JJoAE2FxdgjEdEua+AIGA
         455hQhBOR6RS+v47DWB0D6wI5eGyeP8KFTV0eFOfQRMTbaNUXdDN5VhRRJUzLKDM6oFP
         5KDMPUrdJS0CMhvw4hCjFwj27TOQ3hMgOUKtzTsbvINZKEw8V9UXcB7mt0XhUoZ2byW0
         eoddLRD5/37NJpl2HUI/QufrXvf5RMY0bMihB7M2L6U3WXyM/3Jyvj48xHQrEjbCpvIp
         Ltp0iAhQulLL3CssnA4UYdSOniWZQkHR/jclse5dx9oDElPcP1Zwoc9eCFYOGMbo8mdB
         3Kig==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=L3XJL0VW;
       spf=pass (google.com: domain of alx@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-23de4314a1bsi273585ad.7.2025.07.09.19.49.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 09 Jul 2025 19:49:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of alx@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 9763343E7E;
	Thu, 10 Jul 2025 02:49:03 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A3AF5C4CEF6;
	Thu, 10 Jul 2025 02:48:58 +0000 (UTC)
Date: Thu, 10 Jul 2025 04:48:56 +0200
From: "'Alejandro Colomar' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-mm@kvack.org, linux-hardening@vger.kernel.org
Cc: Alejandro Colomar <alx@kernel.org>, Kees Cook <kees@kernel.org>, 
	Christopher Bazley <chris.bazley.wg14@gmail.com>, shadow <~hallyn/shadow@lists.sr.ht>, 
	linux-kernel@vger.kernel.org, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>, 
	Andrew Clayton <andrew@digital-domain.net>, Rasmus Villemoes <linux@rasmusvillemoes.dk>, 
	Michal Hocko <mhocko@suse.com>, Linus Torvalds <torvalds@linux-foundation.org>, 
	Al Viro <viro@zeniv.linux.org.uk>
Subject: [RFC v4 6/7] sprintf: Add [V]SPRINTF_END()
Message-ID: <0314948eb22524d8938fab645052840eb0c20cfa.1752113247.git.alx@kernel.org>
X-Mailer: git-send-email 2.50.0
References: <cover.1751823326.git.alx@kernel.org>
 <cover.1752113247.git.alx@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <cover.1752113247.git.alx@kernel.org>
X-Original-Sender: alx@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=L3XJL0VW;       spf=pass
 (google.com: domain of alx@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25
 as permitted sender) smtp.mailfrom=alx@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Alejandro Colomar <alx@kernel.org>
Reply-To: Alejandro Colomar <alx@kernel.org>
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

These macros take the end of the array argument implicitly to avoid
programmer mistakes.  This guarantees that the input is an array, unlike

	snprintf(buf, sizeof(buf), ...);

which is dangerous if the programmer passes a pointer instead of an
array.

These macros are essentially the same as the 2-argument version of
strscpy(), but with a formatted string, and returning a pointer to the
terminating '\0' (or NULL, on error).

Cc: Rasmus Villemoes <linux@rasmusvillemoes.dk>
Cc: Marco Elver <elver@google.com>
Cc: Michal Hocko <mhocko@suse.com>
Cc: Linus Torvalds <torvalds@linux-foundation.org>
Cc: Al Viro <viro@zeniv.linux.org.uk>
Signed-off-by: Alejandro Colomar <alx@kernel.org>
---
 include/linux/sprintf.h | 4 ++++
 1 file changed, 4 insertions(+)

diff --git a/include/linux/sprintf.h b/include/linux/sprintf.h
index a0dc35574521..33eb03d0b9b8 100644
--- a/include/linux/sprintf.h
+++ b/include/linux/sprintf.h
@@ -4,6 +4,10 @@
 
 #include <linux/compiler_attributes.h>
 #include <linux/types.h>
+#include <linux/array_size.h>
+
+#define SPRINTF_END(a, fmt, ...)  sprintf_end(a, ENDOF(a), fmt, ##__VA_ARGS__)
+#define VSPRINTF_END(a, fmt, ap)  vsprintf_end(a, ENDOF(a), fmt, ap)
 
 int num_to_str(char *buf, int size, unsigned long long num, unsigned int width);
 
-- 
2.50.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/0314948eb22524d8938fab645052840eb0c20cfa.1752113247.git.alx%40kernel.org.
