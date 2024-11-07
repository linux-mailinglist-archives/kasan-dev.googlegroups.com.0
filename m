Return-Path: <kasan-dev+bncBCKLNNXAXYFBBAWEWK4QMGQEWY4TJQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id C4F6C9C03AF
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Nov 2024 12:18:27 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id 5b1f17b1804b1-4314a22ed8bsf5832435e9.1
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Nov 2024 03:18:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1730978307; cv=pass;
        d=google.com; s=arc-20240605;
        b=YBsLD4XJXgn4+4bjg0TYyKWqTWaP1nNGiElYZtBwLe8yVX8ZHnTwhobJ4T9qTvFsDI
         TxjaQtt6nEGGhk+XDUpWWPh29VeTwaM/KGc+qGZcLM6QPAgGvCDgcgc4wylQAb5E+wQI
         vn45ZxD6wYv3ubhiKJusMl022Tyh5oGrOnPihpMWRkMBLQ4aEa5oxRx7bRIsqaoCKP4D
         xNa2JMFEPUI6sU9CB3Truxyp7TWCAbG0eEEWSyjn6y/X6acwnCm/lAgbsyv3eOMpkBH6
         x9qtpt0FrRvw40MDrYccweo67wwdRZxX50AyykJ1+VC0TTt0EgkbIgm51fZ82wyoVTMt
         wmgw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=M7aV29qa2Uo0Wqb868SkmX+M+3G4Q/MOXqkAh3plqyo=;
        fh=oa00v1fEKkRzrYQdcEX0r1UXHNdWIiWW4Y7SYwvQyLs=;
        b=YYAgStyloGdyJEUivE2BI8CDjsFflrkoF7C19Zeh+VX/aN22F4Pur9yCedBq5ZG+Wv
         0WKGowDLNBSHtFXoXAG/GhVfoogT8mbKlZ8ptqEofXsVv8v02EEm9K7iiXZu8jUCgHjt
         01WQEt61SM4YwYlRicOL7J5zk2w3fZml+tdGx3Y6y299uyr45DXtZygtERC8hI7y+LSp
         GwDZUN4bnc21uAOZdN6u2RUJPh9oGYyAF3MLV2248JfL8jvHGPKYbqkkMkIjDwS7+ZyM
         yrEsZ/K7i021YrDlroIoTY+Dvws3hKbVSVcQ7sMAiL4o26wiuX90Dpc5pknNQ7XT4bb2
         ie7w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=wtsNZeNO;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730978307; x=1731583107; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=M7aV29qa2Uo0Wqb868SkmX+M+3G4Q/MOXqkAh3plqyo=;
        b=jwV6JO0XJ6xIqSGx8fJwcItOHpoQiOBFrTKrUE/w1NTG8P0ngtx/oU2KzIHPpxlJvp
         d2i4zz8pdP50cFfxJlPZHVg3hmitwJe5lXi26+RzPzF3NDBNZOcZ473hP6U4U4081WHS
         rJmNGLvb9ivxsK0whq6VjAe6dtZpyaYTMhlYi1d2sZ7Q6Lc2XwH8alxrz+yTTK1SSkj8
         PlOS8MX4rr1LQ7Xd2BfjDH9XiFInWK5KvmikvW9nnGw+Zl2fOmFS4NMd6zTQjvbn5Kj0
         t1aY7SUbswBbRpG0QrqBI+0AWQqMCA8BLKpDL1eZjNxi1KFHCGg+hKZiWg2V5ZVneWUj
         XLxQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730978307; x=1731583107;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=M7aV29qa2Uo0Wqb868SkmX+M+3G4Q/MOXqkAh3plqyo=;
        b=K/kMxL7+7F+HysHwG9Chpo0SLCUq3ha9sB69jI9i8TTo5rGv/LVWaJU3SzOvZAFHNy
         pX/YximydKGRrOBudZPTfdE1DYn7joYHWyrpMn8LVQ2cxAVdqUpe5BCakV+K3kO3+/Ih
         v/rSWYuRtOYy9DJkBZreepTIjRnlVfisW9RGkJVjJiIwx7kIjcdPXQqVrZbFRyJ6lB+c
         tEEBPqvIVnj5JQoR2+8Wpd4Up+wMOpqy7lnq3+Ofyp22lMF7VbHWnMY4nrgNd5UnMQtw
         vjfv8fi6tlvcYo72liaQMw25314gP0A6MtuKdrMeYmoHkZmFwTz8h/modXa2lqigFVlZ
         L/dg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVIP41ngS5gYpRJVhpo5KU4aoepOtyX3ra3suGVNb0p6eVHPTHXMXmOP+wJV257OJzdUrh1QQ==@lfdr.de
X-Gm-Message-State: AOJu0YxSmss2m6gEb5mZAaWOYnsT+z3J8McjalOviGOGFrAWkiRgJm9u
	AGqWXZieOw+rVER7WHW6wTY6gh4Fge6Nqw+7ffJjxGxv7r9F6RJQ
X-Google-Smtp-Source: AGHT+IFs7kAsXoZHt4sHTIebueYvNsWvFTrbAjr535lVO1d0DGLVtb4cmjfcKnJcPHV31RdcDNYftA==
X-Received: by 2002:a05:600c:1c85:b0:431:5f9e:3f76 with SMTP id 5b1f17b1804b1-432b3015d06mr8217275e9.16.1730978306781;
        Thu, 07 Nov 2024 03:18:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:291:b0:42c:af5b:facf with SMTP id
 5b1f17b1804b1-432af01ab41ls3737015e9.1.-pod-prod-03-eu; Thu, 07 Nov 2024
 03:18:24 -0800 (PST)
X-Received: by 2002:a05:600c:35d0:b0:431:5aea:964 with SMTP id 5b1f17b1804b1-432b3015d27mr8773635e9.19.1730978304367;
        Thu, 07 Nov 2024 03:18:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1730978304; cv=none;
        d=google.com; s=arc-20240605;
        b=jxVN044V/KqOW+T9VkRITgauHCkwhKj7y80J2V633I5iB9MAZnrZHHXwrlQGRFPjvY
         c+AtKueghxIduz9iSX1TkR7upIDBn4DpJyDe3sJ3cyS538a+ISUe14pWeoeL10dQxVP5
         yJOHLBdFQJO2D+JWhVZixKRCJeRbTlmoGWJjcD3pOLS9qjr2N594Wu6Dn5TZ6T/eDvkH
         p4sapjGqSGNCYnpfARUOC9iBczNSUzMhItPyu53vbi/5hnPMi/uEuxwaWYJJ5Mqp8A1i
         EPWYCpiqyMdSjvc1qbp7v5Y7XPI9yBrAXFhPGqqZKDkOU53V+rxGj6KJWO2h4RhIX2sY
         HT+g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:dkim-signature:dkim-signature:from;
        bh=rlnDNt/q+P1z8kgLF+N992bHvMJ9T7IfJZldadLin68=;
        fh=iWXmJmSNHIKwihjAFTZHxJXx+Bx4TM7umj/iDaR++1w=;
        b=TP2fLyGLFEHCDth903cuu3ZGvv/f4ktZlm6Z2Ov7cVIxB9q90gBdq4LxhXEAsabgvs
         JZfNR31o+AxwLw5C2NeSCAWFk9wVkJcFiY/fnT5qQJlPatT+qdrd3q9ufDI+QGh6Rzhn
         PsOE9ykP3fYdiPEL+BfrFmb7JrH54kGBdMNNlujAJsf9X8SqKxXM8XSO2cVYwIKESQG0
         h/kRNIPiQcF3Pf53snhBLmmZ3gemW01/fMIZEsK1mOzttI5i7ritvpxURFg+y1/8xNoJ
         Az9MJMsmYhr+8esSDO3kPS1OU5YyE0mr02u8i1sczXhteuwxc8L+0PRxBOVyhC57gyCp
         aXJw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=wtsNZeNO;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-432aa703625si787065e9.2.2024.11.07.03.18.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 07 Nov 2024 03:18:24 -0800 (PST)
Received-SPF: pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) client-ip=2a0a:51c0:0:12e:550::1;
From: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
To: kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org
Cc: "Paul E. McKenney" <paulmck@kernel.org>,
	Boqun Feng <boqun.feng@gmail.com>,
	Marco Elver <elver@google.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Tomas Gleixner <tglx@linutronix.de>,
	Vlastimil Babka <vbabka@suse.cz>,
	akpm@linux-foundation.org,
	cl@linux.com,
	iamjoonsoo.kim@lge.com,
	longman@redhat.com,
	penberg@kernel.org,
	rientjes@google.com,
	sfr@canb.auug.org.au,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Subject: [PATCH v2 1/3] scftorture: Avoid additional div operation.
Date: Thu,  7 Nov 2024 12:13:06 +0100
Message-ID: <20241107111821.3417762-2-bigeasy@linutronix.de>
In-Reply-To: <20241107111821.3417762-1-bigeasy@linutronix.de>
References: <20241107111821.3417762-1-bigeasy@linutronix.de>
MIME-Version: 1.0
X-Original-Sender: bigeasy@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=wtsNZeNO;       dkim=neutral
 (no key) header.i=@linutronix.de header.s=2020e;       spf=pass (google.com:
 domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as
 permitted sender) smtp.mailfrom=bigeasy@linutronix.de;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
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

Replace "scfp->cpu % nr_cpu_ids" with "cpu". This has been computed
earlier.

Signed-off-by: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
---
 kernel/scftorture.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/kernel/scftorture.c b/kernel/scftorture.c
index 44e83a6462647..455cbff35a1a2 100644
--- a/kernel/scftorture.c
+++ b/kernel/scftorture.c
@@ -463,7 +463,7 @@ static int scftorture_invoker(void *arg)
 
 	// Make sure that the CPU is affinitized appropriately during testing.
 	curcpu = raw_smp_processor_id();
-	WARN_ONCE(curcpu != scfp->cpu % nr_cpu_ids,
+	WARN_ONCE(curcpu != cpu,
 		  "%s: Wanted CPU %d, running on %d, nr_cpu_ids = %d\n",
 		  __func__, scfp->cpu, curcpu, nr_cpu_ids);
 
-- 
2.45.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241107111821.3417762-2-bigeasy%40linutronix.de.
