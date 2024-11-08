Return-Path: <kasan-dev+bncBCKLNNXAXYFBBEOWW64QMGQE5VUN24A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63a.google.com (mail-ej1-x63a.google.com [IPv6:2a00:1450:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id AE6B89C1AE1
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Nov 2024 11:42:26 +0100 (CET)
Received: by mail-ej1-x63a.google.com with SMTP id a640c23a62f3a-a9a1b872d8bsf145531266b.1
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Nov 2024 02:42:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1731062546; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZSy57eHQtd6TmrZ/cAEtdcQIop2Cxvay+eWU5GGT7xyBwcVwvqMtYNZnnEfqKqoLKN
         7A11veJj74A9F7ZL8ktOnLuT2YuFuMpglxAD2A9J9TN+MJi5aRJEn2JPEX62E1qfPuHn
         mud4uP5BoNcRaDDKmxuU3vtic7LAJdR3soxfMBKeKeqtAmBymMtGQalmgQsYPSuWGLOw
         3QvgDr9meSankqQEuP2UR2yT0JqIEUuCPFli8L2PkeTAZYGI/DUnZDWm0T9wtGf68UME
         oNenoCXUoMxZ3UUbB3Fqe80WtbCg3SK+GBLR5kxrchGr2tDZ30vtAzu4RZTKibubHy+I
         +Lwg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:date:subject:cc:to:from:sender
         :dkim-signature;
        bh=bd/joGkAf0sCzSOVgzDuDdB4WrjLRmocZzXw2SIZDEY=;
        fh=r2UskpQTmWss1yy7VBBqk5N7YcymfZKSVaO7z5LtUzY=;
        b=MbCzjv3LtvCm7AW+77V89KQD//iQcpQV2KR8+zqEFHnfIcs9vkya0an/a2TCL6miu3
         iSic06yDymt/nuJL4mMhflmxZ6jWfpwbYM2bZTX1OUdpuL16j59sfRUx7ggXBKoUzM7b
         9iy3DHMZ9481d95KudmkR6zhpReOmqq91N74/QV7oQjbUu2URjxjPJkBdNp43Jw2pUfb
         ur0tmAPlsoHDXuP5zwuLwZ97hjdmkGEvAcMsEnQTZIreiwuoDzF4tj+wqEtma6HJSJ4P
         IGmJAQ/eICl7xrfIkJspmcItTAvTzsTJuyJLnMzlcpJGgMRbtKcz6SX1Jk8S5QViRHOJ
         oLfw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=qfBvYQ6k;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1731062546; x=1731667346; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=bd/joGkAf0sCzSOVgzDuDdB4WrjLRmocZzXw2SIZDEY=;
        b=La8/YcNs4bMQPjEWSTPmFruB9InXhE14xBw5eEZd9+MvUUG1jCSJLzRuvPFb2tBVAF
         fdwtOpalk2DDMx/mCKj+QoMT606OEpXQK2UnSD9n4xnofhulpz7H3sCHpqDCgiPC5VKR
         MshFGOGnooW7JoAMIpr09IZKScOfwekvsVXyjXhlcAvJibdF5oTpU7swNM3rQZRUQ3Dy
         di3ZVw/jxeCdCRPXXNDDcmMe3WX6kjiP6tEJVPAqs02iaBGGeB1+ftKPhAsnWl/SPDzy
         nZV/Nb/wS7o/gXx3T94rD9O98Qs+uKl1jzqBOLFfvZtNV6hpoVZkLa7sU2Wefjns0PIv
         jPNw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1731062546; x=1731667346;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=bd/joGkAf0sCzSOVgzDuDdB4WrjLRmocZzXw2SIZDEY=;
        b=Z6D94SgfW/ezirYkAeqX2KrjnT80ofxG5n0B1TVwNjtCsjR8CVC2qWt/OmXAB4Np30
         MAZg5Kuyr360bbx/16ApLiCvoLJHOBPxJY60J+5GcaiTfmara7XZTL9bvn3WNcd0bc5G
         OGWmurUsS3gxBUODLKZbrKF1jw/zOWNKffsJc7KaqMg0AwvusHtVVXweonlxZRWFV/A4
         y4W0dvCt1faEmBAzmrGZaakMnuNucPGyCuAv01w41IAbkUFjB5QzMY6OB35WK00Tko7U
         NgIz72Jzm4J/k2mO0WWNfC/XxQg7EHssP1VwSZxPze+S0lTM+7jVZIs5y1qTkEpQTU4u
         A7bg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVIntouzC93Hpq3ESPzsbuuBsE90GCqtM8Y1vSGpP7ZzILe/dzSfZ1xG0zAw2R21h0hgVSgog==@lfdr.de
X-Gm-Message-State: AOJu0YxqwngO0mmYpjsKp1OFymH0p1MKGnUIV4eu+TJ55xDxNBjxmtWT
	Kw911bJmYFZNuKiJ6mctGF3UyEx5Vrs1UbOCs9Jxlym5vSFht8ZW
X-Google-Smtp-Source: AGHT+IGkoLj41vVVTBIRvWtavHJ6/plcvqqT0elDwjNmQ318nsqt5SDEV2qi82YUF4WalISPF1W0TA==
X-Received: by 2002:a17:907:724d:b0:a9a:90c:8bc with SMTP id a640c23a62f3a-a9eefeb2b89mr189965566b.12.1731062545625;
        Fri, 08 Nov 2024 02:42:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:a49:b0:42c:b1b4:db22 with SMTP id
 5b1f17b1804b1-432af02d164ls8973635e9.2.-pod-prod-02-eu; Fri, 08 Nov 2024
 02:42:23 -0800 (PST)
X-Received: by 2002:a05:600c:35cc:b0:431:1512:743b with SMTP id 5b1f17b1804b1-432b751b715mr16577375e9.21.1731062543314;
        Fri, 08 Nov 2024 02:42:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1731062543; cv=none;
        d=google.com; s=arc-20240605;
        b=eanQMbp7a07YZytY13/yoe9rzcqwiPPW3dfaT/6JkarszyltxKA5x7edpzUSJ3XUvc
         Ari+QO0RgV7lov5J7mf9k3U7AQXuwn4kKudd4n5nRiZwO+sOuhvm8n9ZAd5vc1LPTM9C
         WyKbWqCaM5ljOOEdHKLnKozT2JPce+KU24/u79eINfdIoluU28aSQF/t3S2bK8EUxidU
         4XCow0BqzKN/FY/vFlFiyvStHqhSl9A+uM8ghzfI80QC02Uocv/i/i5C0hccLN75b5TJ
         onXx1pgvqHnbn740ecTYDNJIJtHzMbhQ5dTbo6FIzM04rn9Gl6nsger5QwoDsT8XWmnb
         mXXA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:dkim-signature:dkim-signature:from;
        bh=Xc/LqlPAYILBsDwML9BEpmuv1miP0xN2teShbWenCQw=;
        fh=MOSuA1H8QGDNXmm4cbnRHrcIY2Uk2qJ1ER8N4n2HqjE=;
        b=fhveUI+pBE5n2DjqhG8xRb/AXJl6LbnKjk6Tcj42jOYCMHiVwr4uJtwKB8gDkXmwrP
         QtyLeLXTVXRVtF4TjtoSlaNMmgI1/7UrGi2nsK6mEXgYHAkZitXqEB70alSQR+dFQyRB
         3TtCLDfxpyaPUzZw+b1qxgVSvT5ImoOuOZPWvUmIdl6sOiP71Ud1h37VCwOLz/7qDcsY
         WgJa+6TiP0Ooit5m2Du4dTFbnFqzG5RY3CoPN5lgGYYCp7r8w+XEJS/+fj5V1fF87jIO
         taJcGkg+IsuJM88m8WER42uJumpjktg4oHbfkWV//Ud5JKjnKDZFJm2DnxPwdBHG+eXj
         bW8Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=qfBvYQ6k;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-432a267d4f7si6265815e9.0.2024.11.08.02.42.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 08 Nov 2024 02:42:23 -0800 (PST)
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
	sfr@canb.auug.org.au
Subject: [PATCH v3 0/4] scftorture: Avoid kfree from IRQ context.
Date: Fri,  8 Nov 2024 11:39:30 +0100
Message-ID: <20241108104217.3759904-1-bigeasy@linutronix.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: bigeasy@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=qfBvYQ6k;       dkim=neutral
 (no key) header.i=@linutronix.de header.s=2020e;       spf=pass (google.com:
 domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as
 permitted sender) smtp.mailfrom=bigeasy@linutronix.de;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
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

Hi,

Paul reported kfree from IRQ context in scftorture which is noticed by
lockdep since the recent PROVE_RAW_LOCK_NESTING switch.

The last patch in this series adresses the issues, the other things
happened on the way.

v2=E2=80=A6v3:
  - The clean up on module exit must not be done with thread numbers.
    Reported by Boqun Feng.
  - Move the clean up on module exit prior to torture_cleanup_end().
    Reported by Paul.

v1=E2=80=A6v2:
  - Remove kfree_bulk(). I get more invocations per report without it.
  - Pass `cpu' to scf_cleanup_free_list in scftorture_invoker() instead
    of scfp->cpu. The latter is the thread number which can be larger
    than the number CPUs leading to a crash in such a case. Reported by
    Boqun Feng.
  - Clean up the per-CPU lists on module exit. Reported by Boqun Feng.

Sebastian

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
0241108104217.3759904-1-bigeasy%40linutronix.de.
