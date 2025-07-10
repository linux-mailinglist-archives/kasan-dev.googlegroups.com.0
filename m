Return-Path: <kasan-dev+bncBAABBEWUXTBQMGQEQATFSFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x239.google.com (mail-oi1-x239.google.com [IPv6:2607:f8b0:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 2E61CAFF70A
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Jul 2025 04:48:52 +0200 (CEST)
Received: by mail-oi1-x239.google.com with SMTP id 5614622812f47-41337bb479asf547416b6e.2
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Jul 2025 19:48:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752115731; cv=pass;
        d=google.com; s=arc-20240605;
        b=O+mPPAEBlJa1hWvpFm7SzuD14nsuG1DFi7f3ziAJBdOH+sjbVPacTqIWRPnAwdlI0M
         yo2vf5RN/u7sSq3COt5kAb6soaD3dHIBxmzLAyXvtdaznaskgwZR6KUNNABU5Q43mps+
         lgG9UQ1T95xP1eVYrn4YdZ4+tDV/xHyuZV0o3mOq3GkB8edgwO7GVCH+n6UGjYsLRP/5
         dO9FJIQpWjGLHw+W+UBh3SoTj5MRU1LLJqHzR5CLF2oR5ewFDGNghRfqkZSBSO5lzhMJ
         skFzTp7y1aMiq0pRzF2h1g26EVFOggD3a7V3DITH6GX2T6z6hPaSD8+dL1jgCpMyrs+e
         c36w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=ugGoloNRdkc2nEhA8ljWaCs+cKzN+qxsoX8w+HlipNA=;
        fh=EknvRzt7EGZSpsCSSuGSo3TlUMxUfcf/TcoKHrfdoWw=;
        b=dBJcrwuHaFK9FqfyvpbhnXBjj1Jk7w2NcgS/4v86m3cdfih5ehrJIYgWoGoeKKCcV4
         TrRONJrqjdpRYqnLKFQyRrI09XWmamiQN4cTdcB/g7ju0HxktsC7qr2b5+YWT6J9U5AV
         GVD/IPc3qSD4i2rg72/owNEL5aYIrmHIx7meIqF8GcMdsQdVMUSvLlYqvUqKLWXIDmjc
         mBaC+ohgso9fUD8kbLhK2G1dJAt3ep3SlKAgtfCBCb+c4RdZFNZKCgZVmeZQtjswjet/
         /cpGuFlTBPyXBlqLwEDm/pnbZBEccSQ2eQ3917ivleqJuK3HtdlRgxjnC3Jn6UD0XXJn
         mAdA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Os+GBNrj;
       spf=pass (google.com: domain of alx@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752115731; x=1752720531; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=ugGoloNRdkc2nEhA8ljWaCs+cKzN+qxsoX8w+HlipNA=;
        b=PctCbVt2k1cfGzIyj/rC4FOCrPF5GTXeOAnlMWLKKFP3T/Eqe2xTk9Ep56dfpMPhxq
         m1x+rduOG3DTCe0JVNqOeYy7VDho5YaZSVHZ7muIsHdYxX6WxT1AjGQl6g17lI5QCfmk
         ZpyKxaHK2SCWI6oB16jnl5+/R+3lzKWiKzLgFWlDbMkRJ2WgZLDUfWGuPkFxktMLlgtS
         CnBjDxqa+FwjPvp6esyFLj3kSvLel7u4xvemFJmgrHs3lSgcnXHzT4Hsk7KuJAlMp8HC
         92dNbmv3YmkUJ2lahPGPAPGfieseYCacec3XBEOV4stsicPo7tK1hA/nGX/OOZFNeWbv
         p5vw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752115731; x=1752720531;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ugGoloNRdkc2nEhA8ljWaCs+cKzN+qxsoX8w+HlipNA=;
        b=Tmv68rBlcCyzv/KXfpGnWtHunHEK1f4ICMRSEEtvQesDLeDVaJpUF3cuvgNjjg/kd9
         re3QQsuFEBdmH9JUNyqczMwy0eR80CZ7ILgMJMVCkI5wNN0tzYKdKSx+rs95UvOka7Qb
         aHUqHitg5Q2k7qDTYZfu0FgLzZ7VbLggH8LsXu9W3DGkGfWxfC59Y5U6qAvrtNB0ESrs
         MHAM4+VATI75J3jeOob98qmIJ754h0s69VzDDlM6aMhHP1EFHwiuybMBZ+FjpsSCOiEu
         kZdNKrB0vifdSsPQmN8S2DCZRAN/Y8sOMHLeiRglFlk05FuhlbbxLs4C8TzDoGtWH+0o
         Jbjw==
X-Forwarded-Encrypted: i=2; AJvYcCV/aow7aUyAbBaReM7gFVEhNKehCz3jiloCxBS92wFuxCfBuEzOSwLnrTwWN2g7CRB23WifUg==@lfdr.de
X-Gm-Message-State: AOJu0YyhaAYrRMz8nj+ekxzOobEI8FJZ/sWmrti0z3Yd74JaeQ3KloyD
	kcWs/xSi2qgcjjy2R7NCvMNnJfEhJagTOyTIPl2aV1vrP+FPMWiQI9Wc
X-Google-Smtp-Source: AGHT+IGyxNt7XvjoF646MX6l4dxvuHVa838sDsWt1Rb1Cr5wvSUGeVBs3ZMqu2MU8noGrVj9+JB+bg==
X-Received: by 2002:a05:6808:4f2b:b0:3f9:76d2:e437 with SMTP id 5614622812f47-413f55ec55cmr827282b6e.20.1752115730843;
        Wed, 09 Jul 2025 19:48:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZf+tkUVEhaEBjFRo9CEFqIwqhYjPf4l3yDNjFwtOyfBNA==
Received: by 2002:a05:6820:40e:b0:613:d549:83cc with SMTP id
 006d021491bc7-613d7b1beaals167877eaf.0.-pod-prod-09-us; Wed, 09 Jul 2025
 19:48:50 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWRepR9VePrQtAe02EAZhTdxQ6ucdGn6VrrmRFpmcdQplbOdyvm3VqUwONUpIJYFhdeEuZCW1GUJgU=@googlegroups.com
X-Received: by 2002:a05:6820:99c:b0:613:cb90:21c with SMTP id 006d021491bc7-613d9faf247mr587495eaf.8.1752115729984;
        Wed, 09 Jul 2025 19:48:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752115729; cv=none;
        d=google.com; s=arc-20240605;
        b=K4BlahfDkyW91uXhUjd00rnCGgK1jDmHJS331qcleD2xeO5MzPfC5a0gKW9DTUhExw
         yjR7cAqcfq9nDg29mdwmoyHkvnQK2TnnjAdfbc5ZGHQaOk33RDDWeivqd2A26rZOr6BE
         rNvQd7p3lVgscpD+kuuFAskXghlaFhsSJM5zmRuyK3bC8vK5+ijqYuZ0s+ucf+4dmv5h
         LAl32QnrsCqMXUi/ld4H935Du6zOK0ynLt/OjlVVYJC0wKz1R8cIOAjrCYvRn29E1AHz
         mCgFABV4aSjJZBKYYjKm/il1O7FlsU6e/cAKupkpOby9Nqu/OAiIkuFkKOmSRbvU5qFS
         YKTg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=ZTzMdAzS0MUZsG3INWu7KjxgVxyuWBJkeq2Ek55G1bY=;
        fh=n7kMCQJrry/6/0/v2g7rS6NiIhn1Yg+3PC4f8tlptsI=;
        b=e0KSrU3CDI8qbTXw2rCrGsRanCIPQu6DXxdFs01m1SSMeC9eRclIEaC912SwOgEbWG
         eldcqkTOg7QXUOfs0Rmz+gTNIDiVUZL25dnszD3c/PlF4+5LoBGpP435gN1fE8w7bQi7
         WnIeIRLTz6q7a+bl5GgJD4HNhq4FFezvloTq1XO9Hab7T9a7OIfWkSleQS8fiDuFUqhs
         W/EKiBfVRaiEK9FP0gDKezGIgZDb38Jv6vW1F61fKG6s3rWQ6cDYwx+ElnePtlQZP7sh
         DIr8O9lbEm/L9JdkR3it/pWzVJBc1AxuIvualMbHwZQHavTgQkX2yAoJUHSzyd3j9w8i
         giiw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Os+GBNrj;
       spf=pass (google.com: domain of alx@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id 006d021491bc7-613d9ca53a6si21340eaf.0.2025.07.09.19.48.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 09 Jul 2025 19:48:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of alx@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 0B52C43CCA;
	Thu, 10 Jul 2025 02:48:49 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 11458C4CEF5;
	Thu, 10 Jul 2025 02:48:43 +0000 (UTC)
Date: Thu, 10 Jul 2025 04:48:41 +0200
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
Subject: [RFC v4 4/7] array_size.h: Add ENDOF()
Message-ID: <e05c5afabb3c2b7d1f67e44ed8a5b49fc8aed342.1752113247.git.alx@kernel.org>
X-Mailer: git-send-email 2.50.0
References: <cover.1751823326.git.alx@kernel.org>
 <cover.1752113247.git.alx@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <cover.1752113247.git.alx@kernel.org>
X-Original-Sender: alx@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Os+GBNrj;       spf=pass
 (google.com: domain of alx@kernel.org designates 172.234.252.31 as permitted
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

This macro is useful to calculate the second argument to sprintf_end(),
avoiding off-by-one bugs.

Cc: Kees Cook <kees@kernel.org>
Cc: Christopher Bazley <chris.bazley.wg14@gmail.com>
Cc: Rasmus Villemoes <linux@rasmusvillemoes.dk>
Cc: Marco Elver <elver@google.com>
Cc: Michal Hocko <mhocko@suse.com>
Cc: Linus Torvalds <torvalds@linux-foundation.org>
Cc: Al Viro <viro@zeniv.linux.org.uk>
Signed-off-by: Alejandro Colomar <alx@kernel.org>
---
 include/linux/array_size.h | 6 ++++++
 1 file changed, 6 insertions(+)

diff --git a/include/linux/array_size.h b/include/linux/array_size.h
index 06d7d83196ca..781bdb70d939 100644
--- a/include/linux/array_size.h
+++ b/include/linux/array_size.h
@@ -10,4 +10,10 @@
  */
 #define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]) + __must_be_array(arr))
 
+/**
+ * ENDOF - get a pointer to one past the last element in array @a
+ * @a: array
+ */
+#define ENDOF(a)  (a + ARRAY_SIZE(a))
+
 #endif  /* _LINUX_ARRAY_SIZE_H */
-- 
2.50.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/e05c5afabb3c2b7d1f67e44ed8a5b49fc8aed342.1752113247.git.alx%40kernel.org.
