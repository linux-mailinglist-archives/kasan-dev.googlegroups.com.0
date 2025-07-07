Return-Path: <kasan-dev+bncBAABBTNLVXBQMGQETWVAZEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3b.google.com (mail-oo1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 7F8ECAFAAB8
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Jul 2025 07:06:23 +0200 (CEST)
Received: by mail-oo1-xc3b.google.com with SMTP id 006d021491bc7-61143269b27sf268503eaf.1
        for <lists+kasan-dev@lfdr.de>; Sun, 06 Jul 2025 22:06:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751864782; cv=pass;
        d=google.com; s=arc-20240605;
        b=O2mhQ2nAU0cXwgdlBq0Dcpk3WxEWbERD1Z+3rxO+UvmtIP5T1mXDcqFKt3DxSnLOZk
         cUTL3XF7jJzFKnoM7RPCkFjiilNsMoPpdmuCy/pKhnHsVIxrq/nzhyhe2Oy9mhPF3GHl
         WDLScktq0MoNJdVaZm42VutlaSc8DOVQ1DizJkMkEHQYliNc0yzsAFMzKTHjH8pVnA4e
         SVv5tMdFJgu+qN98ApOyIPKZEOSVO/8DmvrKLIw3xPkurVlwZilO4N3Poiw0sG1Ya6UD
         glLDwWIZLbyJHY1akt/iIh6wrs7tN0Ca1xIe6N4il+4LifIBGTQpfIJuyCBS+m5AELlp
         XpXA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=dZ4xbl7D72QRMprSeau3he1ft4qMs+CMyHwK0dP6EbQ=;
        fh=/qKQo8omy2GHwGTS9nnNoTg6jAb0JXzrUqsbWpDNC3E=;
        b=iCMgs/iLIXdyG3G2LpXO1jI4qTWK4vtT6J+yxHD0vsMELwPB5fguw6zX7m0ftWKd9O
         i7UK5NnoWVwzXJvuxy/I9E38jX5FrJRepcJcwv3dS4TRi80npNX2vo1i5P48w4cWlBK6
         solscbC3LDX+ndtYX9zCd/JS/v3MAUc9Kfq1Um3dKEQX7NzE2nTxVWRAxIAlaO2UUT3G
         HeEu40vP8l1MhpyOjAzXfjh3HajoOtZQ0lBcv9eJcDY2vvfaMDzSPysvyWyHIcvNugE5
         bc49flvF0Wwd1/fafKIO8msinLXPF19oq8Bgu4IjFUx6oagnU/ObQX7+U55UpFo9kYAu
         o2MA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=VVDyUZ1Z;
       spf=pass (google.com: domain of alx@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751864782; x=1752469582; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=dZ4xbl7D72QRMprSeau3he1ft4qMs+CMyHwK0dP6EbQ=;
        b=kOlf42hGGoYqYJvv4f7r2iYVOXLd0xY9X5cWmyvNCcso2vIuxi2oe5LHDmYBjNrqLo
         t7l3QUACEXIGttigVbuqMtX3OL7A8d4+Pt1sJ41zfY0YhyASk5+KCaLnRRsgy61iTsb2
         nzGEDL17L60qwoiHN9BtKB9U0enw3NySUPYLDZ+7AsJuDsWvOYKAW9TJFLIbajKx2+32
         PuBAYfTY3DyrbXMAW/RuU3+oNbYjMaXECXP4Sa3Tgag2LagWY2QxJmVSED159Oz6Vnt3
         OjR0TDVENzcsSfQ2IvfqFWRvKOJjszJifxY2eoDpryN92gmpYMfWZWIM2LxZ37iOselS
         PShQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751864782; x=1752469582;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=dZ4xbl7D72QRMprSeau3he1ft4qMs+CMyHwK0dP6EbQ=;
        b=scUTPErIkOZl9BET9kV1StthfNGVtGOPECCydg1kK574qXB3yRpyFLDL26Is2oOfWK
         AvTOsLH5rD1TnoEb3gHFZgd+FsXcMidSCHlX+KL0QQXUVBcdGiEx/ZNqTt16m72lMy0q
         0xO15vV4+ecyniJ7plp4sNyymWfsECn6FwkqddUznuOmmLBVO0LlqTYAiyn7UwQsI3Ue
         8TslAUC/Gplw1I9RB3rzRE01MKuYqXKtUfwoIKi93eoWPjL5Gfh+JUWzRLsaKo1fKGfK
         z8lwX1sSpsLUsEXpC8yXKSBcTOo+pc/nQmjhBbBCzkby3GLg1pYjJ1//hW8LwMtmdf+s
         6oLw==
X-Forwarded-Encrypted: i=2; AJvYcCWfrlq2aV0lwlzXO3wBRYJV+NIGA1oUrMklFVjoD/R+RX93/m0KF1zVqHpEWqzmr4+VSMG+2g==@lfdr.de
X-Gm-Message-State: AOJu0Yw1iXBOwvuLICOnRIOpiUplfl6SUO0mnoULHaj0oIoNUMlPMY9R
	1pxthlBefVFkPNmMlzYECxRWlNuWmo/UHvPuUDj+QjprqS+yejA7kKcI
X-Google-Smtp-Source: AGHT+IGNStUgfsj7CCHllNF6EWH3bZTzKkH7GwhR5xZglZNkkcxAHSTQ7SoJMryFSdmNa7fFJMyotA==
X-Received: by 2002:a05:6820:188e:b0:611:cab3:5822 with SMTP id 006d021491bc7-6139ff642damr6048275eaf.2.1751864781870;
        Sun, 06 Jul 2025 22:06:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfcqyzZpA8IRBkFWSeMVJPZsU1Xfp+y7mJS/uCqlfUgRA==
Received: by 2002:a05:6820:2303:b0:611:cba5:4626 with SMTP id
 006d021491bc7-61395926657ls611835eaf.2.-pod-prod-02-us; Sun, 06 Jul 2025
 22:06:21 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWQ2sU/HvQR5V+MMYJmC1tpDaFaIlX46zp20fMx5dUUmvBr5WHmGS3Mt/YGMh+awF/2cvPUfEaIn50=@googlegroups.com
X-Received: by 2002:a05:6830:2709:b0:735:22:7cad with SMTP id 46e09a7af769-73cb44e8756mr4854318a34.11.1751864780850;
        Sun, 06 Jul 2025 22:06:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751864780; cv=none;
        d=google.com; s=arc-20240605;
        b=MS3IDkIj76WCqQIvdCQRaBIqnkIBDxuOhvnQ3ZxXOUCLsXQzeW3ftZjkmPq0A4TlX+
         oMi4TMf11U5hK7Ay1BlPzRN88/AKcYkJNj++jv6tMvBuPXd0ZeSMtNemfBo/8xaGxvkj
         f2Jf/MsR1Eu3Tph7VKxsrxs6jc+iqIEzRVY6Q1liMHG8DhdVeXDW/3meZttNCMKj0yJ4
         StYU/wU7tTmyr2+xmIqSSUUcbQCZai22RKJb7hAk5Ag4aN1B1wkujeXtGgjoqGJhQM+D
         aCYMci/gGBui538Q64cRNGFld6IeY0QXLrXxyxc5thb9dRoQkowys4jErl3VJ3p9IKvW
         ALjQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=ukwhXv43r4Ki9IP9EcOyzjb4aqrTz+kkRm926jdjt8c=;
        fh=bGOSWPRaEaNPf+ttcItAvdRcTCsALM11wypoPWX8Mxk=;
        b=QxDv+sf/bQqP/HvD582VbfA4SseJOlnau5rbLaFoe10XGQ/H8+MlfSH/Pxu5QirpWl
         4B+Qzhzle2r23rAQY4BqKaKWVr+yF/yIYhyKxT45qAKXh6GR+6SL5KuK4F2jrR0LzuwH
         7eKOt6Edn/jweKMpMSqFAQPA+ak51xcgjLD4jhlp/oWSeYyKr4ujlQAQt/bU7Z0T5kjy
         DKUukzVoF6eD4UJALDSWNlbS7jJjTgNGEZwyh5YUvU1SeStA4qPfBMO3qJsz2POrr+74
         2KdVSeFMZtUZd8bGMgNylL4xBynbXzpcoJyav5bKoaPYG0VOuXWCPK6rsjBFefjPz/Bv
         mDaA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=VVDyUZ1Z;
       spf=pass (google.com: domain of alx@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-73cae544e6fsi268682a34.3.2025.07.06.22.06.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 06 Jul 2025 22:06:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of alx@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 6319F61460;
	Mon,  7 Jul 2025 05:06:20 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 19BC6C4CEE3;
	Mon,  7 Jul 2025 05:06:19 +0000 (UTC)
Date: Mon, 7 Jul 2025 07:06:18 +0200
From: "'Alejandro Colomar' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-mm@kvack.org, linux-hardening@vger.kernel.org
Cc: Alejandro Colomar <alx@kernel.org>, Kees Cook <kees@kernel.org>, 
	Christopher Bazley <chris.bazley.wg14@gmail.com>, shadow <~hallyn/shadow@lists.sr.ht>, 
	linux-kernel@vger.kernel.org, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>, 
	Andrew Clayton <andrew@digital-domain.net>
Subject: [RFC v3 6/7] sprintf: Add [V]STPRINTF()
Message-ID: <44d05559398c523d119afecdb3e748d37433fe9e.1751862634.git.alx@kernel.org>
X-Mailer: git-send-email 2.50.0
References: <cover.1751862634.git.alx@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <cover.1751862634.git.alx@kernel.org>
X-Original-Sender: alx@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=VVDyUZ1Z;       spf=pass
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

These macros take the array size argument implicitly to avoid programmer
mistakes.  This guarantees that the input is an array, unlike the common
call

	snprintf(buf, sizeof(buf), ...);

which is dangerous if the programmer passes a pointer.

These macros are essentially the same as the 2-argument version of
strscpy(), but with a formatted string.

Signed-off-by: Alejandro Colomar <alx@kernel.org>
---
 include/linux/sprintf.h | 4 ++++
 1 file changed, 4 insertions(+)

diff --git a/include/linux/sprintf.h b/include/linux/sprintf.h
index c3dbfd2efd2b..6080d3732055 100644
--- a/include/linux/sprintf.h
+++ b/include/linux/sprintf.h
@@ -4,6 +4,10 @@
 
 #include <linux/compiler_attributes.h>
 #include <linux/types.h>
+#include <linux/array_size.h>
+
+#define STPRINTF(a, fmt, ...)  stprintf(a, ARRAY_SIZE(a), fmt, ##__VA_ARGS__)
+#define VSTPRINTF(a, fmt, ap)  vstprintf(a, ARRAY_SIZE(a), fmt, ap)
 
 int num_to_str(char *buf, int size, unsigned long long num, unsigned int width);
 
-- 
2.50.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/44d05559398c523d119afecdb3e748d37433fe9e.1751862634.git.alx%40kernel.org.
