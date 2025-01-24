Return-Path: <kasan-dev+bncBCD353VB3ABBBGHLZO6AMGQEJKQRB7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 4EE37A1AE67
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Jan 2025 03:06:18 +0100 (CET)
Received: by mail-il1-x13f.google.com with SMTP id e9e14a558f8ab-3cfb20d74b5sf11382345ab.3
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Jan 2025 18:06:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1737684377; cv=pass;
        d=google.com; s=arc-20240605;
        b=CrXkjNkv1zDgQFqzpKCjjfjpmgEKIDsrb0eX3nzNKlvj/UJjxzKYePoGNwEW9K0c24
         fmmHlP1oc9bKQY31qvneHZPsEIACalGVQ8noQxdT7EDmn1VQLVujH2p91+IDhSqGjXxH
         SbogyxQU5N2nH2F46MULp6xTA3YCeLmG/L2XV7RNiAJULQWJ60xfU3HI1+ORaiS6mH0T
         4BnjgDKKLCRFTreldSvlhpoUDoldPxWIbs56NHlcXvl4WHkzwup6sxm/IlknKagDL6Ar
         thIsHJLvE0XjR/BoXhIaMaXU4c4jb5K9Qm2PPJfpwzSrQ6RVN6YyUQxP7Yo2n9/qDNjC
         W7XQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:message-id
         :mime-version:subject:date:from:dkim-signature;
        bh=tn0TuMrMrKAjO0oMSvd53nTMPw9L55PYZ+rd9/V3aq0=;
        fh=U59FSCpOI+L7EtLk2nwjqdftEcEmSp8xCA7CmEP7zeA=;
        b=GMEcjTZodymJqggBmA7cJCEzlVKyt0TUPos3lG3MJEjsg/Smkim5HgmOwbX01w/a6g
         A1ApAR/6gS+6UqskT94yNUBbsLP3PgLSkjOts5xsZ4B1Zw/PNq3CjsHFRsGg4OxA9gui
         2NGwIcejIfJsL7WtL3snLX43ntdiPUhiVdscOdVDKBXIW24XtGduSUwtVt5YIB/LKb7B
         LWzk1LBBwzIlOhnxKFzywyKdVLLf6KebiD6kFh684sMHyBg2G2h0AuIt/91UUHt84Zye
         Omrb8RbM03Ym1+0SIcnmfO9jT6C/wtCKXv45kSHyUlF4a67RJrAtFuIHxj2NZ3Un3+0W
         fPAw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=TJTVxsVK;
       spf=pass (google.com: domain of devnull+cl.gentwo.org@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=devnull+cl.gentwo.org@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1737684377; x=1738289177; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:reply-to:cc:to:message-id:mime-version:subject
         :date:from:from:to:cc:subject:date:message-id:reply-to;
        bh=tn0TuMrMrKAjO0oMSvd53nTMPw9L55PYZ+rd9/V3aq0=;
        b=wjLkwuYl3Zs3UK1y25796DaF2mcU3IBTYZJ/PonkJlQDlmDdyT6nFCzVDq3CvOaBGe
         +QD9Z3ve5FhxWO0wfAu6AfJT131GB5dpmeBwUAbXp4F6gk4XGMY9TzPetxGdYvhFojUg
         JkbuXBhdNFb+ui8Ts5RaIPGmxbrmGYn0T7OwhtsQ9mj6oyCAd87kfg5ZB0nh2SiyUT9p
         EYHx96lanszFtuszi4mn9rHr8wzgn/Jf/inXxHar4vekvnk+dDfDKLos0YsFIu4iVl8h
         HvTD0//88beOKKnryOCZdhwgEZa0LVUWAwa8sJsS1UVdMuPn3ULXBOe7xZAJ3rAYJeMx
         fAkQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1737684377; x=1738289177;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:reply-to:cc:to
         :message-id:mime-version:subject:date:from:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=tn0TuMrMrKAjO0oMSvd53nTMPw9L55PYZ+rd9/V3aq0=;
        b=uYoM5UEqEjxLyW1lyQZWDppONaU7Hds5RaL5LGPEAbxzN8XM4ErYuyXcQGrebcHeE8
         yxuvRJG5P/5MX+HI6PmWdEvCdarrgJROdJpQOKdWnaq3unYzL6gHqyFV5piO0LKYSgTI
         qUBpbq1CLWyogG78vUV4IzqcgMy7IbE+IVufgt1npChdjP7/QAdsCDoTxtUOJD82yYlV
         Yu/cqyZpzzejdQYNfIlLiJAOwyjM6VzXJ7Pc5bXBllGpj2PEp0mQea7Izt+i0MlHcflS
         dKZxHtnATUij6W65AiVlyePFjq9sqSfIPgQBu+nngHvrxeAVbggmV3kvedhAz4hmOmeN
         P9Dg==
X-Forwarded-Encrypted: i=2; AJvYcCWaMIV3V+nI3nb9X6mMxPnkUlel3kXEfYhUHYHrsdTJ8YZ7BQ72IFGngWLmXyrIP5mhBFQg0Q==@lfdr.de
X-Gm-Message-State: AOJu0YzWRUV7/JXNCMTXuc1Y0kT0fjaYlXY8ABwXwctzct4si4S8tJlF
	nsO7G2GtUHPhkKPlFckJgjh0S0/BYQlOdfN/VGXHGsz2HOo9QW7z
X-Google-Smtp-Source: AGHT+IEUTQ/HhM1cbfPU1eeVIlj1hLNlmueC+57LhCDmithRuyY/VmWOO8T/vUGFO1+MmV6VcC1iHQ==
X-Received: by 2002:a05:6e02:190c:b0:3cf:b6ae:913d with SMTP id e9e14a558f8ab-3cfb6ae9172mr71163655ab.21.1737684376688;
        Thu, 23 Jan 2025 18:06:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:c750:0:b0:3cf:c8b9:882f with SMTP id e9e14a558f8ab-3cfc8b99e41ls805495ab.1.-pod-prod-09-us;
 Thu, 23 Jan 2025 18:06:16 -0800 (PST)
X-Received: by 2002:a05:6e02:2161:b0:3ce:7d8f:3d75 with SMTP id e9e14a558f8ab-3cf743c9a02mr242417955ab.1.1737684375826;
        Thu, 23 Jan 2025 18:06:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1737684375; cv=none;
        d=google.com; s=arc-20240605;
        b=iQmJ8twwlmqgQAvfU06Nm8MMIahtFzOQwmsHW7nA1opyhSCqhQ9AyxqS5/r9Rovfls
         OQWcsZuO5RlcsD0gBzki3AGGD84AZo6AT2eN6ARY6JohemhvlmZFoj0zz3Au8RH+/d5b
         y2ZMJvoMPbW4B5ctEw2qMvk1CISv2QISDuHS0UD5MD3kjYAqMJVFWOp9GTnT5MKXVqev
         XH4Q/KUOzqhryN7axlNkrb2ru9ewvcvWQPhNdeZpZes/9rnXGHbeciREiMi81yqmWGxY
         O12tEyy4NUDnIcU05/F/ITBCPF6GQHo3TMfpr4Ebdd/3P7PSftVUo/ziQr4BFfKceYJJ
         Nh9Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=reply-to:cc:to:message-id:content-transfer-encoding:mime-version
         :subject:date:from:dkim-signature;
        bh=xgd2Bsbz84B4DH31WEuw8pT4OUp48hATYn6ouTlaKYE=;
        fh=YEiUxUJgyr+w3rjGl3MvT9zXLHpmESnDVGjcSJEZbA0=;
        b=eUYlSJHF7y2UJU/quFQ5rhyDCaqHTgBwAr+zmZPu1dlcO0ukpLlSvBG3GE49KjhlhF
         PXwUrjLvkE9E4y10bXTsgY86pNw2D4RvuihCHHlCVyIMKDz6FlOmAqPRVIKBk6HhrSlm
         Gn9XitCKoY/9MlAqkwuhraiBrAwipCKc2w4ozCtpWnbP3mv3pjML+8RApd0fXi6rFhf/
         v6HHYFw56vL9GSDbcyYFb052crYxxF6kS3lSMfxLRAsjHfr2f2IsKEuVaZVWeAfRsC/h
         dq0FR5Y122IbXI2fXIjVIWqvkaUTkoBMIoDVEIuwm6plar38D6ILOaJpZZQKeskyM4I3
         HzIw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=TJTVxsVK;
       spf=pass (google.com: domain of devnull+cl.gentwo.org@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=devnull+cl.gentwo.org@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3cfc7417fedsi709335ab.2.2025.01.23.18.06.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 23 Jan 2025 18:06:15 -0800 (PST)
Received-SPF: pass (google.com: domain of devnull+cl.gentwo.org@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id EBF375C58E6;
	Fri, 24 Jan 2025 02:05:34 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id E3BA0C4CEE2;
	Fri, 24 Jan 2025 02:06:14 +0000 (UTC)
Received: from aws-us-west-2-korg-lkml-1.web.codeaurora.org (localhost.localdomain [127.0.0.1])
	by smtp.lore.kernel.org (Postfix) with ESMTP id CF96CC0218B;
	Fri, 24 Jan 2025 02:06:14 +0000 (UTC)
From: "'Christoph Lameter via B4 Relay' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 23 Jan 2025 18:06:03 -0800
Subject: [PATCH v2] KFENCE: Clarify that sample allocations are not
 following NUMA or memory policies
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20250123-kfence_doc_update-v2-1-e80efaccc0d4@gentwo.org>
X-B4-Tracking: v=1; b=H4sIAIr1kmcC/32NWw7CIBQFt9LcbzEFilq/3IdpGh63LTGBBhA1D
 XsXuwA/Z5IzZ4OIwWKEa7NBwGyj9a4COzSgF+lmJNZUBtYy0VLGyWNCp3E0Xo/P1ciEpOeqE+e
 TZkIpqLs14GTfe/M+VF5sTD589otMf/ZfLVNCSS/lBftOcdOq24wuvfzRhxmGUsoXICi/3LMAA
 AA=
To: Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
 Dmitry Vyukov <dvyukov@google.com>, Jonathan Corbet <corbet@lwn.net>, 
 Andrew Morton <akpm@linux-foundation.org>, 
 Huang Shijie <shijie@os.amperecomputing.com>
Cc: kasan-dev@googlegroups.com, workflows@vger.kernel.org, 
 linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
 Christoph Lameter <cl@linux.com>, Yang Shi <shy828301@gmail.com>
X-Mailer: b4 0.15-dev-37811
X-Developer-Signature: v=1; a=ed25519-sha256; t=1737684374; l=3059;
 i=cl@gentwo.org; s=20240811; h=from:subject:message-id;
 bh=jDYv6E/8e4wLrb6Ka2L1+EFb9x3w209Y8Bg1u/WHFNA=;
 b=yMoEJnAtIT+qS06EPP9LFWpWtyNaFT6VEzwG4PNqco5oq+djKibhEN80aJush6LDzKaxqmtgS
 Cc0dfy9T3AUAejAwBCeW4rg9fU1G9GwNyEBDxbAY4KggbtWllOlnnOZ
X-Developer-Key: i=cl@gentwo.org; a=ed25519;
 pk=I7gqGwDi9drzCReFIuf2k9de1FI1BGibsshXI0DIvq8=
X-Endpoint-Received: by B4 Relay for cl@gentwo.org/20240811 with
 auth_id=194
X-Original-From: Christoph Lameter <cl@gentwo.org>
Reply-To: cl@gentwo.org
X-Original-Sender: devnull@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=TJTVxsVK;       spf=pass
 (google.com: domain of devnull+cl.gentwo.org@kernel.org designates
 139.178.84.217 as permitted sender) smtp.mailfrom=devnull+cl.gentwo.org@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Christoph Lameter via B4 Relay <devnull+cl.gentwo.org@kernel.org>
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

From: Christoph Lameter <cl@linux.com>

KFENCE manages its own pools and redirects regular memory allocations
to those pools in a sporadic way. The usual memory allocator features
like NUMA, memory policies and pfmemalloc are not supported.
This means that one gets surprising object placement with KFENCE that
may impact performance on some NUMA systems.

Update the description and make KFENCE depend on VM debugging
having been enabled.

Signed-off-by: Christoph Lameter <cl@linux.com>
---
Reviewed-by: Yang Shi <shy828301@gmail.com>
---
Changes in v2:
- Remove dependency on CONFIG_DEBUG_VM.
- Spelling fixes.
- Link to v1: https://lore.kernel.org/r/20250123-kfence_doc_update-v1-1-9aa8e94b3d0b@gentwo.org
---
 Documentation/dev-tools/kfence.rst | 4 +++-
 lib/Kconfig.kfence                 | 8 +++++---
 2 files changed, 8 insertions(+), 4 deletions(-)

diff --git a/Documentation/dev-tools/kfence.rst b/Documentation/dev-tools/kfence.rst
index 541899353865..03062d0941dc 100644
--- a/Documentation/dev-tools/kfence.rst
+++ b/Documentation/dev-tools/kfence.rst
@@ -8,7 +8,9 @@ Kernel Electric-Fence (KFENCE) is a low-overhead sampling-based memory safety
 error detector. KFENCE detects heap out-of-bounds access, use-after-free, and
 invalid-free errors.
 
-KFENCE is designed to be enabled in production kernels, and has near zero
+KFENCE is designed to be low overhead but does not implement the typical
+memory allocation features for its samples like memory policies, NUMA and
+management of emergency memory pools. It has near zero
 performance overhead. Compared to KASAN, KFENCE trades performance for
 precision. The main motivation behind KFENCE's design, is that with enough
 total uptime KFENCE will detect bugs in code paths not typically exercised by
diff --git a/lib/Kconfig.kfence b/lib/Kconfig.kfence
index 6fbbebec683a..1f9f79df2d0a 100644
--- a/lib/Kconfig.kfence
+++ b/lib/Kconfig.kfence
@@ -11,8 +11,8 @@ menuconfig KFENCE
 	help
 	  KFENCE is a low-overhead sampling-based detector of heap out-of-bounds
 	  access, use-after-free, and invalid-free errors. KFENCE is designed
-	  to have negligible cost to permit enabling it in production
-	  environments.
+	  to have negligible cost. KFENCE does not support NUMA features
+	  and other memory allocator features for it sample allocations.
 
 	  See <file:Documentation/dev-tools/kfence.rst> for more details.
 
@@ -21,7 +21,9 @@ menuconfig KFENCE
 	  detect, albeit at very different performance profiles. If you can
 	  afford to use KASAN, continue using KASAN, for example in test
 	  environments. If your kernel targets production use, and cannot
-	  enable KASAN due to its cost, consider using KFENCE.
+	  enable KASAN due to its cost and you are not using NUMA and have
+	  no use of the memory reserve logic of the memory allocators,
+	  consider using KFENCE.
 
 if KFENCE
 

---
base-commit: d0d106a2bd21499901299160744e5fe9f4c83ddb
change-id: 20250123-kfence_doc_update-93b4576c25bb

Best regards,
-- 
Christoph Lameter <cl@gentwo.org>


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250123-kfence_doc_update-v2-1-e80efaccc0d4%40gentwo.org.
