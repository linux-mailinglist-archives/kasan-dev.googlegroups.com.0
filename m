Return-Path: <kasan-dev+bncBC6LHPWNU4DBBUPESS4QMGQEXTOXTOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 117EF9B9913
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Nov 2024 20:56:03 +0100 (CET)
Received: by mail-pg1-x538.google.com with SMTP id 41be03b00d2f7-7ec0d56d624sf2560351a12.1
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Nov 2024 12:56:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1730490961; cv=pass;
        d=google.com; s=arc-20240605;
        b=OleOHQ7Yw2beK0KJTG/sTAsO/XaAEKieXgPCiLifW+MqOplYN74YxeFqpIumpaINxp
         iuTblRrDepTBzZPrqFlADeQFxMi2anyAQCvfyhRK3CyMU7d9WQRYKvRxReJl40mFu2Di
         kD4clIsXZUG9lg3fK36RrX72MUwJ0x3RNCRH3SEEblsf2VnFgi/mlISLNSCIEEJrkFVi
         8SvikQjJ0ccZ5xP/JnMytysccc+mPnJgRHdwedqUfWJz6aoCIJcV19DTv8/C+NeH53/j
         KhA/YuCClBEkmYfqn9gcA809v/2fkYUH9GtfVL/A7SkrKJlwvw/k2Trm8MCrNNaDzrwv
         q7Vw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:feedback-id:sender
         :dkim-signature:dkim-signature;
        bh=ihNcyxmSrr+mTBMCEqCjykgCrYp9BpCC6t/152a9PIA=;
        fh=TQ5O2JQ6mZKrwSCvh01KRBPeDhZfXQ+roS8oTKTfINI=;
        b=ft5pM7QYzBXubJDBn+NAWn2pb7EhbzUyASsxGY7eYSm4k4e34zD04Ioxas8N0N1Cjf
         PgMB59jmrxUW1l6KRyay/spJwhXk1jWjCPYi+IGwT/xnW4AS1fznO1u1Q9u68f7yklp3
         3nQIOUbI3/1UYnGB0YV20IlFBwjJCJp+EsoDpqGGehJvE/7R0hNEIBQJAqxepIsg4G25
         mVJHVJHSJ80un5WM/Qd5Xdup+SkqwAtMtvxZwTYyesjGiY+JMJ0RFWh6l/uNFXdyrICz
         0wPJ6n7CCyPpW4ijGqoBt/CuHqXQvYcMcIDufPYmlIAcGkzakRNRNLewL7LsE1TIF2nt
         p62A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="P/9ZXGmB";
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::72b as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730490961; x=1731095761; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:feedback-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ihNcyxmSrr+mTBMCEqCjykgCrYp9BpCC6t/152a9PIA=;
        b=dOgXceB+U++qE3SnmaHXiITxdwCWznk1328bwy/H1bkg8G+YN+7e3IJM2tnXYpKv6z
         oTQoxLEuridEagFS2NTOG7lhwEUZfH+RopGZkeKft6yInH2b7qIHZclVYQFBLPKhnN/P
         7PeN8C4JxQ64Zw/VS30h0xtKRouDDXgKi//Ieuag2TFoJk4q3bfP882DaRwfAyaqkX3i
         I35PocyR/U9tAdijorNz44sMKCZw3SU80B4rMDEdjOh8kdAEWzF8Eh0at54pAUeDGzDE
         VTYzRFP0FSUgksHNUhXgVbttcw6WqmOdhaXuXbpGyK4Xgxrcye5PhQBh7pHe5bj6zCxg
         kJKw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1730490961; x=1731095761; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:feedback-id:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ihNcyxmSrr+mTBMCEqCjykgCrYp9BpCC6t/152a9PIA=;
        b=Rz7s5tyHwKAdeRaByn5uN6B0Xz+Qq4X5DY0XUSQyNEI8hwDFEtebxw/7Z3jzLjYwu1
         Hfbj+FkWBGVEYLo7+gIggaqvLtedX9ql37hdD3NxwNWmu+Bg11hoI9dq8Vn1Qbg0WnJ/
         kHH3n47El8kWVaOENCMLzBbzj8BVYKpr9j+Qxxcp/wyy78bJ7/VXCOgUUsAmxXvEhZzz
         CrbiSGjolvOT4yGbyFl74ke5Rcmd99O5Amtkg+fmm89NuDz0VclmayZNMD5b/jCi6nf9
         RY78I6onHiKj31okakzIWPQB3/OCFaScscDjdyGwX37+4EzK0PCIiVsqan8BAi355Vf+
         usEQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730490961; x=1731095761;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :feedback-id:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ihNcyxmSrr+mTBMCEqCjykgCrYp9BpCC6t/152a9PIA=;
        b=gp5IhRWrgFjDPUBJP478Agm+UHn4+Zvyd89IO0Hb4rK2TX9zdlghtQ35wtGIQzL4Cp
         Tpk6cLyQpkBGrCtBsw/DoMv+aMLbVQJWwVb0mgSZl3sifR26x0S3UEHV6zbo+bJXbD07
         Dkp9Apk9VUqQuahQdOMbxYXd2qs39v6T4bbsmTR45gN/zwVQo4exF8GwkaLOytO+RLoy
         qPihfGSF5pb4uzn6nHUCX/yX26G6zdj5wuXdLAoXVwN1k1Hq3EpRcI3cRI6y/0rQcoKV
         gAcgOW6RRVu4CcJN8pGHnjC89Po+FBkGCR7U7Rxjt33uXpIBzveiqrDgy5cB1qX4bFhL
         kcyw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWEjTs3jCHsONDFOxWe6WX6+6a3UBPeb1HmHl8KMEr7mye+oUCiij/dYVPen1psTDEe9BgsHw==@lfdr.de
X-Gm-Message-State: AOJu0YwjzpPW8MSm7sqQRyLR9Dg9fwCTpO3VwaCUEUFyUGQwUQONE11A
	+iQrDepBI8yIWsGcDKYPKLrrCWlGgmqO79f0yPi2JGziFOaWw4K3
X-Google-Smtp-Source: AGHT+IHQNdXL/9ooQ2xa78IBzzzmgoBaL4BuEbN0WqXtI4CvM5H6kd98NWq9jaHBUfsVYzrz/GzTIQ==
X-Received: by 2002:a17:903:11c5:b0:20b:b40b:3454 with SMTP id d9443c01a7336-2111ae2bebemr48540375ad.0.1730490961210;
        Fri, 01 Nov 2024 12:56:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:f145:b0:1eb:1517:836a with SMTP id
 d9443c01a7336-2110362f40dls14414065ad.0.-pod-prod-06-us; Fri, 01 Nov 2024
 12:56:00 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU8ngl2idqm3q/BXsUPNvfHm0tcdUlB/7mI61LkQHAt8zU9xRhzfOeKiWRlf4r81aDVkAf5zN4e9Pw=@googlegroups.com
X-Received: by 2002:a17:902:d2c4:b0:20c:8331:cb6e with SMTP id d9443c01a7336-2111aee4561mr58006535ad.19.1730490959889;
        Fri, 01 Nov 2024 12:55:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1730490959; cv=none;
        d=google.com; s=arc-20240605;
        b=lgSbiP61SsVV2ah/IVrgoaZc12JddnqBt+eL69KGs4PLJrwI411IfYKQpu4PBKm0tl
         z8V57teZHJuPGIXmz15K2zftmDPxeoQW33QRuIsBKPjaWIHuWrgPBjplmCoYVxPEY9wg
         kGrhBHIM1ndjXuQDZGh7gG5FTQ21O0OMr2xnmRmjm8qCZKkcaB85TrguI4z0i8l8LspW
         /4ahxlQNepRwHmrhGH2PHFehSJs00aKWiQ/jsG3smEGJKrUfnA7ajHAoQVJcDMU61QKg
         R2IyZq7+y48RbjjReZYP0eh8NICe8ZBncf8FOJPOX/ST+Fj3BhrtBA/1p371DLLRk6PY
         861Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:feedback-id:dkim-signature;
        bh=V/wo6tn5xum2AVMECmALlIc/sY7DW4M/ZUa/SRoull4=;
        fh=gYuuV47OIN3mWDGB6FhwFpC0slxlZlXEewtGj/jEbP0=;
        b=FlKJgKhjMTgoYdhUYOOnlN5GsgOVtUh8Xl68dHUHP26dYZgXLeJBra+t5DLo4D8yLJ
         7r2S2CwI/mX0GmSBQeInc5bFHyBD2LnJmp/Hii+ccXj1STDm8th+WWZiqJQeL8n7BpSL
         2jr1xFgvMpe3lLHz1Q2zMWduizLJTsfYIultnTQ0+n8XsX3bGU29pPt34Xa8tlf0nPXh
         3oCMbnPhKduuO9nbKPhMlA5PXAkOSHgJOYZIHpHvFwuHQzxqRLc8V2M0DxcMsnAIkDLV
         lsp60b6qYi0Q6pG52veb7/Kf2hBDSfA5diYE5EAAM2mD7N+Nb1O/4uS+QzOun9fV/BVx
         IVbg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="P/9ZXGmB";
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::72b as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qk1-x72b.google.com (mail-qk1-x72b.google.com. [2607:f8b0:4864:20::72b])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-2110572d9easi1675625ad.6.2024.11.01.12.55.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 01 Nov 2024 12:55:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::72b as permitted sender) client-ip=2607:f8b0:4864:20::72b;
Received: by mail-qk1-x72b.google.com with SMTP id af79cd13be357-7b1434b00a2so175013385a.0
        for <kasan-dev@googlegroups.com>; Fri, 01 Nov 2024 12:55:59 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUkct0Gyso6QfjQmaUOku74hNDB/ZAnsUkb/qM+2no/eYLqINdBPqUxbLdGynXeDblZXSe3gOzESq0=@googlegroups.com
X-Received: by 2002:a05:6214:5d86:b0:6cb:e52c:c8dd with SMTP id 6a1803df08f44-6d35c1aeed4mr49651226d6.53.1730490958752;
        Fri, 01 Nov 2024 12:55:58 -0700 (PDT)
Received: from fauth-a2-smtp.messagingengine.com (fauth-a2-smtp.messagingengine.com. [103.168.172.201])
        by smtp.gmail.com with ESMTPSA id 6a1803df08f44-6d353f9e057sm22585066d6.1.2024.11.01.12.55.57
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 01 Nov 2024 12:55:58 -0700 (PDT)
Received: from phl-compute-10.internal (phl-compute-10.phl.internal [10.202.2.50])
	by mailfauth.phl.internal (Postfix) with ESMTP id BFA231200043;
	Fri,  1 Nov 2024 15:55:57 -0400 (EDT)
Received: from phl-mailfrontend-01 ([10.202.2.162])
  by phl-compute-10.internal (MEProxy); Fri, 01 Nov 2024 15:55:57 -0400
X-ME-Sender: <xms:TTIlZ8lfSP9MlcD2F7JoHfhkb8lAwhsYzyVpORFeF-VXmzm1x6_U3g>
    <xme:TTIlZ716IZvAJDG00a88vUMfuZO1KixMaUrh67zEOouvT9PPu68CGYHnE1GlnrCXi
    D2Cr6mmD9yQvuSetw>
X-ME-Received: <xmr:TTIlZ6poIyW29YzSYk9Mg8DgHN0SekWjuh3OyvaprNHa2cG_2lZTCKVkxNGH7Q>
X-ME-Proxy-Cause: gggruggvucftvghtrhhoucdtuddrgeeftddrvdekledguddvlecutefuodetggdotefrod
    ftvfcurfhrohhfihhlvgemucfhrghsthforghilhdpggftfghnshhusghstghrihgsvgdp
    uffrtefokffrpgfnqfghnecuuegrihhlohhuthemuceftddtnecusecvtfgvtghiphhivg
    hnthhsucdlqddutddtmdenucfjughrpefhvfevufffkffojghfggfgsedtkeertdertddt
    necuhfhrohhmpeeuohhquhhnucfhvghnghcuoegsohhquhhnrdhfvghnghesghhmrghilh
    drtghomheqnecuggftrfgrthhtvghrnhepgffhffevhffhvdfgjefgkedvlefgkeegveeu
    heelhfeivdegffejgfetuefgheeinecuffhomhgrihhnpehkvghrnhgvlhdrohhrghenuc
    evlhhushhtvghrufhiiigvpedtnecurfgrrhgrmhepmhgrihhlfhhrohhmpegsohhquhhn
    odhmvghsmhhtphgruhhthhhpvghrshhonhgrlhhithihqdeiledvgeehtdeigedqudejje
    ekheehhedvqdgsohhquhhnrdhfvghngheppehgmhgrihhlrdgtohhmsehfihigmhgvrdhn
    rghmvgdpnhgspghrtghpthhtohepudekpdhmohguvgepshhmthhpohhuthdprhgtphhtth
    hopehprghulhhmtghksehkvghrnhgvlhdrohhrghdprhgtphhtthhopegsihhgvggrshih
    sehlihhnuhhtrhhonhhigidruggvpdhrtghpthhtohepvhgsrggskhgrsehsuhhsvgdrtg
    iipdhrtghpthhtohepvghlvhgvrhesghhoohhglhgvrdgtohhmpdhrtghpthhtoheplhhi
    nhhugidqnhgvgihtsehvghgvrhdrkhgvrhhnvghlrdhorhhgpdhrtghpthhtoheplhhinh
    hugidqkhgvrhhnvghlsehvghgvrhdrkhgvrhhnvghlrdhorhhgpdhrtghpthhtohepkhgr
    shgrnhdquggvvhesghhoohhglhgvghhrohhuphhsrdgtohhmpdhrtghpthhtoheplhhinh
    hugidqmhhmsehkvhgrtghkrdhorhhgpdhrtghpthhtohepshhfrhestggrnhgsrdgruhhu
    ghdrohhrghdrrghu
X-ME-Proxy: <xmx:TTIlZ4m4t81ppoFkr1cmCCtO-kX1jMBtvxUNA1VDPYPtlSe12f4gAg>
    <xmx:TTIlZ61slM-2eqUFtvsYX2nqG5HU9amq-00y81a_5kHjGQBtpZ5hkw>
    <xmx:TTIlZ_tPOHLdbUAWQtUfJZs685NaXBieXXS2vAS5OjSLUN7ldnRMEQ>
    <xmx:TTIlZ2Uh1xEeem0Q2YRoJ5ZmWADRB6auQXBl0vGA0ksX75uUNSRoXw>
    <xmx:TTIlZ93CZkjDu_5S3-pgsYBzXqo-5C55WchluOkC13vjJYGwm494Wx2L>
Feedback-ID: iad51458e:Fastmail
Received: by mail.messagingengine.com (Postfix) with ESMTPA; Fri,
 1 Nov 2024 15:55:57 -0400 (EDT)
From: Boqun Feng <boqun.feng@gmail.com>
To: paulmck@kernel.org
Cc: Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
	Vlastimil Babka <vbabka@suse.cz>,
	Marco Elver <elver@google.com>,
	linux-next@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	sfr@canb.auug.org.au,
	longman@redhat.com,
	cl@linux.com,
	penberg@kernel.org,
	rientjes@google.com,
	iamjoonsoo.kim@lge.com,
	akpm@linux-foundation.org,
	Thomas Gleixner <tglx@linutronix.de>,
	Peter Zijlstra <peterz@infradead.org>,
	Boqun Feng <boqun.feng@gmail.com>
Subject: [PATCH] scftorture: Use workqueue to free scf_check
Date: Fri,  1 Nov 2024 12:54:38 -0700
Message-ID: <20241101195438.1658633-1-boqun.feng@gmail.com>
X-Mailer: git-send-email 2.45.2
In-Reply-To: <ZyUxBr5Umbc9odcH@boqun-archlinux>
References: <ZyUxBr5Umbc9odcH@boqun-archlinux>
MIME-Version: 1.0
X-Original-Sender: boqun.feng@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="P/9ZXGmB";       spf=pass
 (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::72b
 as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

Paul reported an invalid wait context issue in scftorture catched by
lockdep, and the cause of the issue is because scf_handler() may call
kfree() to free the struct scf_check:

	static void scf_handler(void *scfc_in)
        {
        [...]
                } else {
                        kfree(scfcp);
                }
        }

(call chain anlysis from Marco Elver)

This is problematic because smp_call_function() uses non-threaded
interrupt and kfree() may acquire a local_lock which is a sleepable lock
on RT.

The general rule is: do not alloc or free memory in non-threaded
interrupt conntexts.

A quick fix is to use workqueue to defer the kfree(). However, this is
OK only because scftorture is test code. In general the users of
interrupts should avoid giving interrupt handlers the ownership of
objects, that is, users should handle the lifetime of objects outside
and interrupt handlers should only hold references to objects.

Reported-by: "Paul E. McKenney" <paulmck@kernel.org>
Link: https://lore.kernel.org/lkml/41619255-cdc2-4573-a360-7794fc3614f7@paulmck-laptop/
Signed-off-by: Boqun Feng <boqun.feng@gmail.com>
---
 kernel/scftorture.c | 14 +++++++++++++-
 1 file changed, 13 insertions(+), 1 deletion(-)

diff --git a/kernel/scftorture.c b/kernel/scftorture.c
index 44e83a646264..ab6dcc7c0116 100644
--- a/kernel/scftorture.c
+++ b/kernel/scftorture.c
@@ -127,6 +127,7 @@ static unsigned long scf_sel_totweight;
 
 // Communicate between caller and handler.
 struct scf_check {
+	struct work_struct work;
 	bool scfc_in;
 	bool scfc_out;
 	int scfc_cpu; // -1 for not _single().
@@ -252,6 +253,13 @@ static struct scf_selector *scf_sel_rand(struct torture_random_state *trsp)
 	return &scf_sel_array[0];
 }
 
+static void kfree_scf_check_work(struct work_struct *w)
+{
+	struct scf_check *scfcp = container_of(w, struct scf_check, work);
+
+	kfree(scfcp);
+}
+
 // Update statistics and occasionally burn up mass quantities of CPU time,
 // if told to do so via scftorture.longwait.  Otherwise, occasionally burn
 // a little bit.
@@ -296,7 +304,10 @@ static void scf_handler(void *scfc_in)
 		if (scfcp->scfc_rpc)
 			complete(&scfcp->scfc_completion);
 	} else {
-		kfree(scfcp);
+		// Cannot call kfree() directly, pass it to workqueue. It's OK
+		// only because this is test code, avoid this in real world
+		// usage.
+		queue_work(system_wq, &scfcp->work);
 	}
 }
 
@@ -335,6 +346,7 @@ static void scftorture_invoke_one(struct scf_statistics *scfp, struct torture_ra
 			scfcp->scfc_wait = scfsp->scfs_wait;
 			scfcp->scfc_out = false;
 			scfcp->scfc_rpc = false;
+			INIT_WORK(&scfcp->work, kfree_scf_check_work);
 		}
 	}
 	switch (scfsp->scfs_prim) {
-- 
2.45.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241101195438.1658633-1-boqun.feng%40gmail.com.
