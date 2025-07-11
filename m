Return-Path: <kasan-dev+bncBAABBB67YHBQMGQEEVUDJCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73d.google.com (mail-qk1-x73d.google.com [IPv6:2607:f8b0:4864:20::73d])
	by mail.lfdr.de (Postfix) with ESMTPS id 9A47BB01109
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Jul 2025 03:57:28 +0200 (CEST)
Received: by mail-qk1-x73d.google.com with SMTP id af79cd13be357-7d097fd7b32sf348073085a.2
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Jul 2025 18:57:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752199047; cv=pass;
        d=google.com; s=arc-20240605;
        b=Ei9jsXCY5FDYeCwsUxhN7mOKzmY6Zt6qQTMwjqK+fNc3TNr1pnG3v606ThJ/1WGaDw
         NA5M/p3gWjq0tzUwdu6qpqbgoCfkFOkOYWiFwM8Wn9/exHeHrJ8cS59INQ6/1MR3BH4Y
         rCzSYRQYtDtwir+ok8RMJTJAsZIMscn66DnXmgAPf+JreOEhnmEjLcvLrBMVghuHnuvN
         jjAJJg+sY9SGZtG/VMSTUCZ2/BbYiR+6ggxXy+9TxD+lmkw9P/EZe1Bz41QcR8MTGbJ2
         v6FbXpEErADQBN1Crna0NIMcF0RUq0CO1pHpZLstcjMjq2V2DYQCu2Gimo4b6wehsJH2
         6Hqg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=LjaqLMpENLZRADXW+qJjoGL9Oq0Y7FQbQ1OMMM9bx+0=;
        fh=OsOPoz7x8M6mZ8mVum6iFEQ7b6/WqP6Zi7NYrO4P9bk=;
        b=KvX0oWP2BmxdLqMqmp/aZRp1L9io8sfBVu0KkVBoo2QGf4AO78riuiIQ+W51ATnP5v
         2YvM/saGBOvl7lXjt0/UR5jIRVVyc84/L/uuEK5sIyycmr0nqF/JXM+dM5gknQ8YlNDt
         1xBXyyxfClpkJXcrnOqtgTXk5eTMcZPGwFXW9CkFSa+ERXV/UGY9Sq/OfdqUHHv/Yhxv
         gyBHdBj7yVbh+NuD+P2whpifV956MJO2fll7mGEGTq019LLM9iuytpuWKkDjrC5sPwO2
         fHDlou05TJ4eLHsxtQ+Rd2cN3YF5T6MWxamA6sJFxf2TsjvCs35kA9DOJcRnjGXWaZJO
         z1GA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=roC9g9PB;
       spf=pass (google.com: domain of alx@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752199047; x=1752803847; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=LjaqLMpENLZRADXW+qJjoGL9Oq0Y7FQbQ1OMMM9bx+0=;
        b=lWi+Ccrf9XyixqU90h6E5e39ChANCS/Ngt7IofyIUnW38v8BXqholo6I+bai/W12J4
         2PVnAZQwglUZQ1VEdrm0hGaeJHFGEhnezvtgkCQR2+0aJjQf77b1RWwkF4Q3kJz+IrU6
         oTzwDt/3oz760AVn/LA3TPCuinkTpNVlGeqbzP9RZknMHblsBXkNYsFmUO8bVbSzPTMh
         mfRL2YcYN3RgJjP4mvtX+Sx0/sIExU203VhBytNNrtthQK3u0vIpOTbuR10uT6a30FVi
         H0kLDhhwRPD5XGwp78xSgMMqdT6vvQqDG73VrrmQ6aaQOna9h2RctNz9I5/P+4BZR5VQ
         SjZg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752199047; x=1752803847;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=LjaqLMpENLZRADXW+qJjoGL9Oq0Y7FQbQ1OMMM9bx+0=;
        b=oj09QFGAo+SsuzgqQthvNTVd4xaoAYPA6K5gzdYD/mjRUKTg+2hWeppiHTn7x2VJXa
         LqSKFoEWpgxo3uqe5h1M8O7LxCfl0s4K/LcA4YapECH4rZP0VIrRvUq7/zhFOwnC+r/6
         iiUJKXNQIv9kzjehPp1pAjHeUWzjqUq6/4Gi2nOahXF59hXbinCF7df3oVFkF1Mz1wqc
         AAhhZ4ZMxI51OXbqWNFsd8wLDhRSHYbIxjwB0cCG6qFz1XlQCp90bbpal9J/PxWvpbNQ
         S5QAiwL8aQwbVrPFtS00VvZEjD2JMG2n36hmNRfmKGRxA5kYsHhMQiuq/80gV3Ie1/6d
         /oyw==
X-Forwarded-Encrypted: i=2; AJvYcCX7o/eTIvqNU2HnxXU1LcHR4JxQofHb5lZu6Aenhq0QeQ1fHW4IO9tf2dDa9k2WXfXkcf7UkA==@lfdr.de
X-Gm-Message-State: AOJu0YyVaNOCsbcQflHwHf2iLghRO9uvq16JD4X47ZLfpljW6tJfhvmL
	77e7WPADa/lUbSYtVP9m51PfkwxSyoN+VbVcNv+arKDOBoakhLPZYMN8
X-Google-Smtp-Source: AGHT+IHZo0kYfDwxueSqSZx9TkpQzx0ZqWtujEHPzQPFk/IyZyHoVYU9Elqh9aSzLS64TMyMbx2xxA==
X-Received: by 2002:a05:620a:1789:b0:7d0:a0f2:e6b1 with SMTP id af79cd13be357-7ddebc93478mr271869485a.32.1752199047276;
        Thu, 10 Jul 2025 18:57:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdiANI8hfOxLSIkmRhEKq82tFlG4iLcIoKwZ4M6uI9WHA==
Received: by 2002:a05:6214:ca5:b0:6fb:4b71:4195 with SMTP id
 6a1803df08f44-704956ee3b2ls26882786d6.2.-pod-prod-06-us; Thu, 10 Jul 2025
 18:57:26 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUXsT2Fp7Z4nVZmi46+AL3UmeVNubtXdpmZLsFfHv0jOLml6hD1Ck/cPk2UiclJlz26g7ffKdSZdP0=@googlegroups.com
X-Received: by 2002:a05:6102:2907:b0:4e5:acea:2dec with SMTP id ada2fe7eead31-4f641170beamr1328978137.7.1752199046075;
        Thu, 10 Jul 2025 18:57:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752199046; cv=none;
        d=google.com; s=arc-20240605;
        b=htxEyqRWLsY9VVtj9RdhLhz4LfzzI9ychEkuTHOvTkeYwHerydWiwXpfC4Qrg6U5RE
         5aKiW2vHTQzsuj8uSVHrQw8TSJADY1Ne+b6B2vt65oX0rLRdQqvWbQualq5x+t83sV9p
         bHDESyYVYl/G2mYaNpc7NC5/bzgiub408VeVg8JgZv8/PnljNSD27+7rJC15WvpTGztg
         qHp9iMpGI1qmDdrDsQ4mZrs6Xj6uq3CeQ9mmjIU0RnJcvrow3jWl5R5s/6tywhTHwxo6
         DJa6RbkP/sz/ZzScer0WUR3PneK0c1bSCMCkQvEV2kQMMsaGYmxpb4lEAgAGVGKygXYH
         Hsgg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=kxlwBtIVhGWZ8OoO7pHlpnuOe3FSmc3gWsDT8zjGSd4=;
        fh=3xnUY8A2Mq3PveV1ZEc6h+AgvXyG6cfw9LnpDv9FfXA=;
        b=ZIDFx6WmNoezYachbkrtwrQnK2LuIg4acDu78nXoUnptdF5vZhjJdd1xRFpGj2QHTE
         zMpZh0n8xoQsN/J65HOY5glbd2PhiTPPNEmLU1kLcRJS3HqK2lr1sTZ5b4TS6xLvGm6P
         gP6cIVZMvok+pQi7LjkHdciYuaULeVU3FkZhgEzWSGyRO4+bUt+oAoiaqRP01SE8iP/d
         ss+5IlcTZlJejK/k9wpQKRs3P9h9oTX5xN/LNK5oHdFCzzFYzm25VFVsuRva+r/Vysu6
         okvKfjJMbi9RtTJ7pFCSLXtDc8QkPFBMGD3QnFKUcLrheMlSZJLodJ0V5gvTJxfaAwt7
         pc4g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=roC9g9PB;
       spf=pass (google.com: domain of alx@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id a1e0cc1a2514c-888ebe257dfsi35273241.0.2025.07.10.18.57.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 10 Jul 2025 18:57:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of alx@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 920926154B;
	Fri, 11 Jul 2025 01:57:25 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 922DFC4CEF6;
	Fri, 11 Jul 2025 01:57:20 +0000 (UTC)
Date: Fri, 11 Jul 2025 03:57:18 +0200
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
	Al Viro <viro@zeniv.linux.org.uk>, Martin Uecker <uecker@tugraz.at>, Sam James <sam@gentoo.org>, 
	Andrew Pinski <pinskia@gmail.com>, Jann Horn <jannh@google.com>
Subject: [RFC v6 7/8] mm: Fix benign off-by-one bugs
Message-ID: <c88780354e13d8531f4f4118f251a070de7ef13e.1752193588.git.alx@kernel.org>
X-Mailer: git-send-email 2.50.0
References: <cover.1751823326.git.alx@kernel.org>
 <cover.1752193588.git.alx@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <cover.1752193588.git.alx@kernel.org>
X-Original-Sender: alx@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=roC9g9PB;       spf=pass
 (google.com: domain of alx@kernel.org designates 172.105.4.254 as permitted
 sender) smtp.mailfrom=alx@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
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

We were wasting a byte due to an off-by-one bug.  s[c]nprintf()
doesn't write more than $2 bytes including the null byte, so trying to
pass 'size-1' there is wasting one byte.  Now that we use sprintf_end(),
the situation isn't different: sprintf_end() will stop writing *before*
'end' --that is, at most the terminating null byte will be written at
'end-1'--.

Acked-by: Marco Elver <elver@google.com>
Cc: Kees Cook <kees@kernel.org>
Cc: Christopher Bazley <chris.bazley.wg14@gmail.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Jann Horn <jannh@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: Linus Torvalds <torvalds@linux-foundation.org>
Cc: Rasmus Villemoes <linux@rasmusvillemoes.dk>
Cc: Marco Elver <elver@google.com>
Cc: Michal Hocko <mhocko@suse.com>
Cc: Al Viro <viro@zeniv.linux.org.uk>
Signed-off-by: Alejandro Colomar <alx@kernel.org>
---
 mm/kfence/kfence_test.c | 4 ++--
 mm/kmsan/kmsan_test.c   | 2 +-
 2 files changed, 3 insertions(+), 3 deletions(-)

diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
index bae382eca4ab..c635aa9d478b 100644
--- a/mm/kfence/kfence_test.c
+++ b/mm/kfence/kfence_test.c
@@ -110,7 +110,7 @@ static bool report_matches(const struct expect_report *r)
 
 	/* Title */
 	cur = expect[0];
-	end = &expect[0][sizeof(expect[0]) - 1];
+	end = ENDOF(expect[0]);
 	switch (r->type) {
 	case KFENCE_ERROR_OOB:
 		cur = sprintf_end(cur, end, "BUG: KFENCE: out-of-bounds %s",
@@ -140,7 +140,7 @@ static bool report_matches(const struct expect_report *r)
 
 	/* Access information */
 	cur = expect[1];
-	end = &expect[1][sizeof(expect[1]) - 1];
+	end = ENDOF(expect[1]);
 
 	switch (r->type) {
 	case KFENCE_ERROR_OOB:
diff --git a/mm/kmsan/kmsan_test.c b/mm/kmsan/kmsan_test.c
index e48ca1972ff3..9bda55992e3d 100644
--- a/mm/kmsan/kmsan_test.c
+++ b/mm/kmsan/kmsan_test.c
@@ -105,7 +105,7 @@ static bool report_matches(const struct expect_report *r)
 
 	/* Title */
 	cur = expected_header;
-	end = &expected_header[sizeof(expected_header) - 1];
+	end = ENDOF(expected_header);
 
 	cur = sprintf_end(cur, end, "BUG: KMSAN: %s", r->error_type);
 
-- 
2.50.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/c88780354e13d8531f4f4118f251a070de7ef13e.1752193588.git.alx%40kernel.org.
