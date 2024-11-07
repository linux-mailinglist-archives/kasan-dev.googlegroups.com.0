Return-Path: <kasan-dev+bncBCKLNNXAXYFBBAWEWK4QMGQEWY4TJQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 154819C03B0
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Nov 2024 12:18:28 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id 5b1f17b1804b1-4315c1b5befsf5376325e9.1
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Nov 2024 03:18:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1730978307; cv=pass;
        d=google.com; s=arc-20240605;
        b=ghicB0axCbJS8xJvoaaiunmN7kt2Q8OGGPR3hzplWSKE1zB7a6hFOt88J9tgtqmuvR
         Opw9Xx98VLBBe+rK7iCVcjklC9vHrTt2CCpTklF4vz3G7+RfODUnPL2wuq84HhPXax9J
         DXtmFi3kTA7Mca3JCgWqpYH2fFYsl8PjvaOJ7ZF7Z/bRoreqwcTUdnb79+sgf+6nSrhd
         sQNUC9zJV2hUfKu+UxGPhplVs/jq39XpBRhkL700nX6yMwxLUV55x5rV8hhlcc99yp7h
         grDJ5ilakeOKmV42Q30akLCRPSMzSXYPwfBucVUOAHP6hasX/7f+VuMU6W+jB95DSfHV
         E2hg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:date:subject:cc:to:from:sender
         :dkim-signature;
        bh=c3IUa4aFWJe3rj0X5AO/CBa1j0XqABBpE9AgsZEwCBg=;
        fh=OQFDfygG6OgXooO0GUDm4Aks3Ut98H/tS0NNFyS8FDw=;
        b=HNYOhqByfxS4o0J+2KngB6V/Z1og4aKlh4ovSJa0Yj4YXi74fJ44n0FcN/SIwiddrf
         xryNNbG8Q99oP0uBVBxfcYt10Z2mIPPfeqFe6lsOZmP3ovsVQmODbp2WoI003wY0ICh3
         kZQWszmRJNaFQmtUkCoQtM8WNtyMKzcb/8wz7WCZLsl1i0PCFrAkO0RDUBSNBzS2WH2T
         /eTnUxESkCv6hP92QV9Eff12HmnPBP/fWSCTVkJorWgVvy8RJ3pPmmHgW0jISQ8LWs2W
         S7jg4e5fMQTOkNl0NH/msrnqgEfbQvV8QSPyT2AiE9rSfknsioJK417OsB+/HgHfidri
         Usfg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=RcCsSVC6;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730978307; x=1731583107; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=c3IUa4aFWJe3rj0X5AO/CBa1j0XqABBpE9AgsZEwCBg=;
        b=wEZvMjGS8+rt/Omxa6f06znoSkVJahFSjZLrLRZpTk/RUtJohXg+j8oR4lAkPS6iuo
         Ezf8DnWkXBbduAvKaDv7G/FK9yJi6tXy1RsLbSZJswAGdduCQzyBIqz/tfeY67pqqjw1
         1KmuWMU3CIntXmAzXUDDbJlso9XTdV9Ir1Wv4Zvenm0B4Qnk3KThKG4CUbNxgwrFOkH7
         qXNOwjGX+6F24BOPqXbTKi4WEACOe8G8alYex3+shStZqDJgD61sIqgmlomEKQzderM6
         5hfzCc99Btd/3KdvZeO6OnAEFUyeZxcXn8mTtRzTnzfec40/AT9ajobr6I00va6gyPpC
         dEfw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730978307; x=1731583107;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=c3IUa4aFWJe3rj0X5AO/CBa1j0XqABBpE9AgsZEwCBg=;
        b=WVjn9EAT8jLRDoYlAZ4l7kxomv4Kfo7+alSBhkT8sYNrYp8z2uzygadTNMmdz9OFBA
         iOOPVCCvZh5JmI4LiYIbd/qdTw81Ua10tSE6AIHDruKvsackbEMnsT01janVLW32UGoN
         Z2My3GuVMetJF+pz4jMBKzd472V327ctrVkD3IJEK4Za4idS50LfUubKwVseGgvLdsBl
         hJ+a8S8mHnjqDv4zYmO5Rp4PqeE+pDlQaO7y6597gRyDLuGpND70k7vXoS7a2myh4GXk
         Q497Ybg9i9tcl557I0uPr4Co00rwqqFMeG3VFoxGZaiocGDWJyBdp70g5OLRzOTzoggz
         lIIw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVTG+AJVvxEvl/QIzsvrq9jDjwBc0E/4Zh5CdVWiQfD3FMYjTMPz+niJvYZXjxRGrxmSIGZLg==@lfdr.de
X-Gm-Message-State: AOJu0YziiWK7KsfUw75YtF9LlwIeGBTkbGkhB71JB4pJ+1QjzqHT4Vpf
	EA5aHpqtwlGHbJdvOHF6qqiCg7uvdW4ht+K2DCHHesIvPOFUAqR1
X-Google-Smtp-Source: AGHT+IFg1espocOXmE7xlqRDbO1JL9A0LYj1CPjlSctMrmJnxlTpMsV1VyQv74zwVrDh+BQh8hqcAg==
X-Received: by 2002:a05:600c:354e:b0:431:547e:81d0 with SMTP id 5b1f17b1804b1-4319ac9ad43mr372877815e9.11.1730978306737;
        Thu, 07 Nov 2024 03:18:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1c87:b0:430:52af:6691 with SMTP id
 5b1f17b1804b1-432af022397ls832325e9.1.-pod-prod-08-eu; Thu, 07 Nov 2024
 03:18:24 -0800 (PST)
X-Received: by 2002:a05:600c:3c8c:b0:426:60b8:d8ba with SMTP id 5b1f17b1804b1-4319ad04990mr359662335e9.28.1730978304223;
        Thu, 07 Nov 2024 03:18:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1730978304; cv=none;
        d=google.com; s=arc-20240605;
        b=QiaxrVJXERCGrNd8Y+P+IlHVQg8VuOKIl74qoXnl8QXwbf5WAybLoykDJTYaI6a4dz
         vICaKOaeUfLcTvBVy+c7WjNAMW9LBVgYV0WQV++Dqcn1nac8lDBcjzGjYC2hbVE2xdGM
         30x2toRToyiwe43ly0AqdlR/8wWlkaxar8QgPrEVO79QIuyUSMc+Gd9bvahl3VDZa3wl
         NJgz/FOWlR9nn9oBPVkuNABH28Y4vAMEZt3xhwaXuYQ+3ICRi5c6xH0jFgezQ8S3jMUg
         DXDtDHpr2GiJllGFT8bH6BaJHN5AgxWfqwrZuqPqj3dTfNaH/U0TY/pDqhjnM88s3a0h
         zfPw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:dkim-signature:dkim-signature:from;
        bh=NjLLP55ROdVW0XOMGkfmixpDUwgnQl08mDjZ5Jht+U0=;
        fh=MOSuA1H8QGDNXmm4cbnRHrcIY2Uk2qJ1ER8N4n2HqjE=;
        b=YxgGfa7vok+GlaZcsq6xbXVoZHfwd8h6X4x70KrHjG8fvU/uijC933jIo4DktEAmpv
         BSwnyE+CO8WUPKAjvhYzdG3Ud0+7Cyeu8SwttXUcuW5bhMsmAbd5PAUhcIufxNuPP27b
         wdYWJ+EAlNxtiWsbt9Zgl2z0GAlcnfJPcFhNYTurTR7c6jrl1Vm3EWGzhM3r82d1ejT1
         J3fx3PtL7dzvLWdC9kuGC1Okt7mG+GmehenLBod1MCEvBoQgJFxgsEgxMXwk3uyMulrz
         vcXVYk66Zzo7Q9rfipLCQ/GE3KRkAy7gs4ew3vY6nxBTXgQ6hDBzAg7ismtvsVLpXFJM
         hiCA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=RcCsSVC6;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-432a267d4f7si4411595e9.0.2024.11.07.03.18.24
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
	sfr@canb.auug.org.au
Subject: [PATCH v2 0/3] scftorture: Avoid kfree from IRQ context.
Date: Thu,  7 Nov 2024 12:13:05 +0100
Message-ID: <20241107111821.3417762-1-bigeasy@linutronix.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: bigeasy@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=RcCsSVC6;       dkim=neutral
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
0241107111821.3417762-1-bigeasy%40linutronix.de.
