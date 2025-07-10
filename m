Return-Path: <kasan-dev+bncBAABBLPCYDBQMGQEWZQFCVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 2B7C4B00DD9
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Jul 2025 23:31:27 +0200 (CEST)
Received: by mail-qv1-xf3b.google.com with SMTP id 6a1803df08f44-6fb5f71b363sf23570576d6.2
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Jul 2025 14:31:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752183086; cv=pass;
        d=google.com; s=arc-20240605;
        b=MeiQTqWRYZUsO3X61ijjppZqtQu2dIMuV5nDYY8U7NTCuj+xndFTYEcb69EwiKbFdp
         VAQ1j26GtuHCfmDhYXKT/1dSKBBEVNnYdWJ0QjVfWsC4uVTbokm8AbJOu+V/z6MAr7pL
         YMWsVY3CabM9WbIJiJqL0sV4MBkygJoZjVxIgP+sxw5jwMzKByXTCHI1rrzOKaDvpRqd
         9QbyUz5YD5XH5gj3sbhu+dhGkawEyL69lJWzFmUVG/lMg398pagYz5UwxLsl9oEE3F3L
         ydn+BptqP5tusKwxLcDpzTdr3Ip7N+LgO3WsajOIJMIwfjkcZnnpdZ+tJd5rWVUUpTJv
         V9fA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=LqHg5R0cSndq9C/gOL6ml7kLO32WKR2X+oDblpJyAD4=;
        fh=IW5ZZoIHVB0ZfF1pcF9Gw1PyQ9trWWj7L1gs5qeQ3xQ=;
        b=ad5pmLqoL5AdV2AzlgFcxoqeVcIsxFXqxunxDSkZvf4q4BcWQ4y4CdSdpDP75NfFA7
         upeKNPrcQf0X4C55UpDpdU1aatky63Tdtcu/+wEQZvSY3Bgd3bI4GU15G5nveCkJWC5E
         gXmlcqxc1Ez8e5Zlo3+sBBvW0K4GLaY4Eq3KxbGs4AH3vCQaV0id2+h6XcMstKGQJL/N
         ymaLwz9riTTOS1u5vh2rJLeg4Z4kfazrIkLEg4pugg2PaYfyT8XBR6MeJwT3xxiDe0m+
         o0H8eAfZw0CQyGwRcfhuR4e6usxBZ0FhmlF7NRl8lNucM0WMdUsHxftnY2x9Bk77q+Jj
         vApw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="Czr/vs+w";
       spf=pass (google.com: domain of alx@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752183086; x=1752787886; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=LqHg5R0cSndq9C/gOL6ml7kLO32WKR2X+oDblpJyAD4=;
        b=aVbwGQVhej0GrBhIYp5ZQNJ6fwQ7JAFHsnuMAmjhH2vcM412joXoHVTbEDF7eDsuFM
         rkAwicpKPLo7jNtEKCPX29Z1jnrtLN8Bp83fyt6roIuuusNyCXHWu4IvPEhA/Rqh+Jhv
         XJuqNS3hsaq9XFG4OTAMf0Q3iD3vF9exRCoAYcpsiOTwUorQumKmiSFPqFPdehmgQplX
         tZUnv9HjUrtviL2IQF/+L/daGOLT09mzNQuyI3d9B2pWAVeM0377Q82hqtOOaI3+b7a3
         5UHG75NlYMv8BWyv9aAU7ClJfylj/TjFfHl04YxkIUjxr1GxBL1bnimz93QhHhUwsaUG
         OFVA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752183086; x=1752787886;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=LqHg5R0cSndq9C/gOL6ml7kLO32WKR2X+oDblpJyAD4=;
        b=j9ZVeVQb3izfGlUGm3V0oK5PerteZUWkbH+CWT0Jl5rInRnDwFWGbB/xB0l0gYDekM
         X+xZPpIWtZfBJAWJ4heX+s6qDMEmlIU8tFRKq2i7tZTiV4c0LlUKx49wa3Q0ufySh5OL
         OcsZrnpVFjTi6WQB2FOenrrMEtgB9HOQCcf2Tk/KjBcy6p7xekiK+tEFuMMfRglLAXVX
         9cnZohsbOMFf0WIAlnop1DnCEHsj7NvD0Nqir5xw1q1wYX47L3l0JZcjWV55H4QCWh/F
         u9uOMkB2RMxVXUAKyjAu6EXJScl+Pkp8dr0FM6K8C+71f7zHFjdvbjKIchSJgijzNGIA
         7MAQ==
X-Forwarded-Encrypted: i=2; AJvYcCVI/8OG7Nrxdxvc5rVG4HZaTAZhF3HgOXvnuhs3e2NndveC2Xuae9dV+PXtjpsS7YsCY4g/bA==@lfdr.de
X-Gm-Message-State: AOJu0YytnoOeEvRhvRlULLQlItj7UrokhOqMsCHtsiQE0C9kxXpwfMPc
	F8kfMFscd0WzABKshyenXdzDBQbYaCfD2PsWOiGrUyCijczVRPR0VUFY
X-Google-Smtp-Source: AGHT+IEFogAa53LTLcFjzQbJUlYi7mQtUQa8ugFZUmSGZUvK5SD/2G7MsKziKAKIlVBEBAG3tmu5Wg==
X-Received: by 2002:a05:6214:dc1:b0:701:a1c:1a3b with SMTP id 6a1803df08f44-704a42b144cmr15887246d6.27.1752183085797;
        Thu, 10 Jul 2025 14:31:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfeqEFUc7FCzUgviqTg5wBsnGSCc+7RTB7JJ6+jXycPbA==
Received: by 2002:a05:6214:acb:b0:6fa:c0b0:1fa7 with SMTP id
 6a1803df08f44-704957369fcls24359876d6.1.-pod-prod-07-us; Thu, 10 Jul 2025
 14:31:25 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWcFL8+eq/II05runVGtWLNRmM8ZZs24Ba1HcHpzXQ5TbzcxRlmEu+aAxCppWigeJH9vxwufVU+tW8=@googlegroups.com
X-Received: by 2002:ad4:576f:0:b0:702:ca9e:dba6 with SMTP id 6a1803df08f44-704a40f3f86mr14579276d6.16.1752183085152;
        Thu, 10 Jul 2025 14:31:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752183085; cv=none;
        d=google.com; s=arc-20240605;
        b=GS79lbs76lF8bhF74SMRkbrpECY/GeRR+ADv7vth/rkMruHwfq7GWaaU8k9LTKSmC4
         XNIeaEGC81reAoy/anDR2Tk3hojkGI+pnTWCZajIrk+a5Ui4XKqiO9F6vVrnyfe0C+EL
         rZf7cUxcudsegR59DovQzDLH8dMZqzD8T5S/iL+2K4VJhkFSwNnqOMm0RIkBCiPkL1+T
         XYZq+hIvQylEBaUKve8B+uW94sb+ugnOEeUc1h4127uWBroYSbtqGBnfFc6HGb3k1fkC
         iS46fpGDPknaWOltJCda9aAnL5cSqLdvoCxsxOU6ppLWg8CjDuCPQ9V1tNHhIhjk+PpD
         jtKQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=/ToJt/WvylXgUGvZjgaM3dJY9CyYuzUOshtzeK38clc=;
        fh=QOnzKEUq9WcvM0XNCrg2hWMbQW8+1K0P/8Aq77keZA4=;
        b=FfU3drH6TJL5AlBsSfDI5Q+Qf/t4uc/aoQQ58NFHoQ/0psWHDOSfxqfmjM2iZH02RU
         Pnx6+utHWYMGYGXlIRaP1NCEv96a9dOV9t1ADoJcaDi0IiwavYzy6nVEIchO813NNtg4
         lqK8A4MYBSpokGNth2aSrDNs3AnHi4o8BA9Du7kg009aYf0/om9YwuR4gN9SObqkbE5E
         vHZMW/fnCHvrGP1pYXhYPlkJvYLHs3k0oT8XXq9ICGLcQcY5bqkN5XRZVlh29MYsMtZY
         QUMHO8riWbzcw6up1I1CXn+CPAziPxlkJAYYAfRF3aErf/oWkue1/sHnWniSpJkKGnBL
         o5Jg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="Czr/vs+w";
       spf=pass (google.com: domain of alx@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [147.75.193.91])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-7049774d23dsi1184716d6.0.2025.07.10.14.31.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 10 Jul 2025 14:31:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of alx@kernel.org designates 147.75.193.91 as permitted sender) client-ip=147.75.193.91;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id DAB1FA547D5;
	Thu, 10 Jul 2025 21:31:24 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id EC03CC4CEED;
	Thu, 10 Jul 2025 21:31:19 +0000 (UTC)
Date: Thu, 10 Jul 2025 23:31:18 +0200
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
	Andrew Pinski <pinskia@gmail.com>
Subject: [RFC v5 6/7] sprintf: Add [v]sprintf_array()
Message-ID: <04c1e026a67f1609167e834471d0f2fe977d9cb0.1752182685.git.alx@kernel.org>
X-Mailer: git-send-email 2.50.0
References: <cover.1751823326.git.alx@kernel.org>
 <cover.1752182685.git.alx@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <cover.1752182685.git.alx@kernel.org>
X-Original-Sender: alx@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="Czr/vs+w";       spf=pass
 (google.com: domain of alx@kernel.org designates 147.75.193.91 as permitted
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
index a0dc35574521..8576a543e62c 100644
--- a/include/linux/sprintf.h
+++ b/include/linux/sprintf.h
@@ -4,6 +4,10 @@
 
 #include <linux/compiler_attributes.h>
 #include <linux/types.h>
+#include <linux/array_size.h>
+
+#define sprintf_array(a, fmt, ...)  sprintf_end(a, ENDOF(a), fmt, ##__VA_ARGS__)
+#define vsprintf_array(a, fmt, ap)  vsprintf_end(a, ENDOF(a), fmt, ap)
 
 int num_to_str(char *buf, int size, unsigned long long num, unsigned int width);
 
-- 
2.50.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/04c1e026a67f1609167e834471d0f2fe977d9cb0.1752182685.git.alx%40kernel.org.
