Return-Path: <kasan-dev+bncBC3ZPIWN3EFBBJPEWDBQMGQERW3E3MI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id E01C1AFBCC1
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Jul 2025 22:46:30 +0200 (CEST)
Received: by mail-wr1-x43f.google.com with SMTP id ffacd0b85a97d-3a50049f8eesf1603766f8f.3
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Jul 2025 13:46:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751921190; cv=pass;
        d=google.com; s=arc-20240605;
        b=Vt/poDqdQK/mcDoc9Wpfnd8lSZuWtsgOk0kQlFItFGsR/bVvmMKHbB4j2cKE9IDZrz
         udiFVDYHwnEn01Di2ed3QcYTrCh/umYM6P9j8Hf6GulPnHMzDnSNXu0gQsMenegu7ENi
         5dS7kFT9o6ybC0y3xSTG/8DiJD7n17iuk0JalnIqrLyQhIhlGJ3V0zhmwQxcm6YaULm0
         Q53SB/41lfXMXzrlFcxTo986Koc0z5L/8Weyxww/uRFcWejKilJh1fqd/Y8JRKLGCw7a
         rI7QwzE9+PQN0VbwCXR7a6fUjLFrART7Enve4RAkLiGzQ9slxA3T+IV9CWTHO2jnge/G
         Rrjg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=ZRDZzDvBpUTMTi1B69rfEnoPe7W2dOsQCV6I3z0L/bE=;
        fh=eJu65cQ4sz7uML6AjMP9CmJk49UrCFYG3KF6SEvSXYg=;
        b=bK3K4VAF6fZ3imSjmsF97oVGVaoA1Ra4S5B93trszfDjlw/E3eAgwnF73bCKEkh28o
         5aY+3zkaKbELVwekA9G6qdVVMtNAR47rPVdhkvnpR5/SGB9Ir/y4YqL1oKUhdYofFwoS
         1TKrUZRrOR2Um+Yj2dUmQqAF7PvqiDmb8++z4zqime/HVFRZwACnY3bqonataDmXbcj0
         x8m4aEcgFZMXTeF9941u6yTJrzumbNT1jo4ZQp3gs6mofNY0FNpHLdGtmwhlEvCoS7d+
         3XXpGxED1wBueYUsiD3X23a60e7c82EpCT7rvX4pAmXnhIp+imwuEvWV5NBw36dZc0ZA
         Tgjg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=CgAptjk1;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::636 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751921190; x=1752525990; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ZRDZzDvBpUTMTi1B69rfEnoPe7W2dOsQCV6I3z0L/bE=;
        b=xJR5BkygNdnSgN0lnwVaSXLy0klYiR+rnVVbQt0qFHPdpKKEOX0/2O+0wuzWNig7vY
         mSZUq3SyV2WJ9qa3E2eOc64pL3jdyAiAkEMruZxPakgUlKwFrlo2UUgq2xsxLfehCDCK
         hZAun7uKDY7GqEAQ34A7Lorof2d/l8pCopGgTBJmseZUzDi9AvBrMl5r0WUU3LYNStFh
         x3KE0p7K3ZE8eSNiamsUHFIYrV/tzjpHY4aNX8IxbJe3Lb5e7AsVVCXLTWtbw06+RfrZ
         X+ZnXzAC3gwkOF6YyR3j4AWWQ3M9lOdYHYV4aoH4tWgqMaDOKMeDmsBBtcRx1Fnfljna
         JoAg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751921190; x=1752525990;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ZRDZzDvBpUTMTi1B69rfEnoPe7W2dOsQCV6I3z0L/bE=;
        b=U/B8xevVpCAMAhQ87yLB7vBrkYy+FRnGaAK52bkRIbYPPlpOQnzbVHG2yJsSEckAui
         KB5162N0W2BaTZJj2hGLnTswOzS55hqOxuvI9CT55/1V+oku/53hT3La74J2OP+QLcME
         +0um8lpZp02F0C5RpODGrGTIaHlUC+l8IZDOUWjbfHbEtDTyZoSq4TP6QSEUUIDfnPs6
         eAE71RU4SzjGR+D3m6S+lzZyw5X/vKaAFA1WJON5qsAexYiWgllkm+y3dfoTCfhUCjYi
         ViUIaK+1V9Ax+7X11f5fN24WLGjj+AA9ltE19qbxdVJxHwafPCNjp2aMoFpn30MppmzF
         0LZw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVu3DiP0ldBhKkj8XBjTFEpQGrIYxRx3JEyJGGVADrd6DUse0SN+THWzkVZgxetqex5KCcgHA==@lfdr.de
X-Gm-Message-State: AOJu0YzXMfOi+wgGgeOlbcSYUDlQ12dwlDVzCMs2lKhZSshMqNqBDt//
	46HsYs18LxUXwWrpd+XGgA5xJRYvzV3Az4C6U0mrUObOQT7DeQv877RB
X-Google-Smtp-Source: AGHT+IEaGIwOmprMf/fRezf7c51hSiJXeSIr+O33O2mWoDzhHcMzhdu/0fW/JwUSQFl/7WI1uffNrA==
X-Received: by 2002:a05:6000:2111:b0:3a5:2cb5:6429 with SMTP id ffacd0b85a97d-3b5ddedcb81mr134161f8f.43.1751921190119;
        Mon, 07 Jul 2025 13:46:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfsxw8J6EeoP7Ffd7Mj0/cP83ZBDvtKcuhRD6F/BatpmA==
Received: by 2002:a05:600c:3e0b:b0:453:dbe:7585 with SMTP id
 5b1f17b1804b1-454b5d08b39ls16486345e9.1.-pod-prod-04-eu; Mon, 07 Jul 2025
 13:46:26 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXeDtiA/i2D9oIu4d5o+OJ/dILTY5Ru0HL+EElmQULSBbrOSNMSo9s9YQZ9bk4Bpm7ist0v33VrFBA=@googlegroups.com
X-Received: by 2002:a05:600c:1c1d:b0:442:dc6f:7a21 with SMTP id 5b1f17b1804b1-454ccc78867mr10759485e9.3.1751921186742;
        Mon, 07 Jul 2025 13:46:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751921186; cv=none;
        d=google.com; s=arc-20240605;
        b=bgSxFSuyUZjugHHtGy2SvMe5FLB1W5t8N0LgorzG5TpG44svTSG+eT8WH5LQ68gyMT
         kXykNz7TQAlAs2v985pbfmJ1u0kbIYCz2b/G82cFOziQ716IYEbk6KHtmGHpWqpfkU0j
         2Rza4TfowdU5BVS2NENDp8vICwznvUcGUAS1G7VSHuKSVvCLN2ktuBgM/aezVXkW8OdB
         aferjx+njuLEvvmEN61LTsDQHsRFeCb3P2WxDXilzSWmMVBTtwZ1JGMDM7zT2+FdZYHO
         0QUFwQj/drQ7bXFHbl17j20LRu8cr2g3VvpCl5QCOogU/xxcwu3vVaPtTle1a9FUCt2L
         OeWw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=yEDgBaUeWk+QDb/AaNEeMgvkFy6FrKw47awCwo707GE=;
        fh=G+uF57U8ejt7GXRJDgPPzq95TEQFPO6PddC0v1K+bhc=;
        b=Ec/SAnDyIai9xSEFEZrI5TVfH2BlB+kpJ7cPzmlv60qgIuN1prsJJqgmsd+vsM9JcL
         ysF32Z120CZqWX58BdmF6a93laS6DSrt8AWMsNmAyzOiuPKkSK3R58+84dAcymU7UNLT
         TYaOnuWCoHGafqiGXk0KiwgT1QPiyx9KlX1TZe0wSCkJmf/JFVMmnH8bq2UyB9+svkXQ
         JMtEb03BxBxcbyiM/L9q6o3AKNoALQamwgNXG1m1tCZv0v69TZY/zZ0irKE8C2nEBrhN
         gjEDzOH7VsCy8e3x3L8bCDm5/jDPDcBfDZeWe1bnjf9SbzSPxZnis3Z1VYjzWTSlvAJE
         aKWg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=CgAptjk1;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::636 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x636.google.com (mail-ej1-x636.google.com. [2a00:1450:4864:20::636])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3b46cff5ef9si282479f8f.0.2025.07.07.13.46.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Jul 2025 13:46:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::636 as permitted sender) client-ip=2a00:1450:4864:20::636;
Received: by mail-ej1-x636.google.com with SMTP id a640c23a62f3a-ae0bde4d5c9so747671866b.3
        for <kasan-dev@googlegroups.com>; Mon, 07 Jul 2025 13:46:26 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVqMna+epFKx/vk7NxGQ0B9CB+Zz6ixUXJvjq8Y74L8Hok+iiFsnQS/C0Au39ndzVFALzTG19///jc=@googlegroups.com
X-Gm-Gg: ASbGncsxGKJHGItVC2DkMw8hFovj0DCvS62uy9QNhTqlBCaig7dN3EsOQqOUgKtLgF6
	e9abQaAtbKitFs3guARbhPoxwH2mmHc8zy87UJVIbpWouTb+n3H7M0pQgRNMTrgvXPy9l4wOps5
	NlVIiwcACEOl5vahLMKLPeZ6WX/ZEVRv92mSB53X902Z+/R+62/w1BEgg1vpydYT3uf1dtfYFSi
	c0yWDj+nhlFHomAO0qBnMcboZXEWFpPJPUvSBq9Agkgf09kybAMNtwsKKJ9LTxINcX7WO2Si42h
	kFX99/VpyK9aEy26KzXcqzAYoz5cMPWKHk9cfd4k1dw8ckqboyEsnYcgpCSQ9vVqucqYuHMPt/l
	Zh0Nbq4JWuCv2HSkkVIb/70/KxytrntPD3i5J
X-Received: by 2002:a17:907:d7cc:b0:ad5:4806:4f07 with SMTP id a640c23a62f3a-ae6b0049633mr58881966b.2.1751921186172;
        Mon, 07 Jul 2025 13:46:26 -0700 (PDT)
Received: from mail-ed1-f44.google.com (mail-ed1-f44.google.com. [209.85.208.44])
        by smtp.gmail.com with ESMTPSA id a640c23a62f3a-ae3f6958586sm764844766b.72.2025.07.07.13.46.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Jul 2025 13:46:26 -0700 (PDT)
Received: by mail-ed1-f44.google.com with SMTP id 4fb4d7f45d1cf-6097b404f58so5257837a12.3
        for <kasan-dev@googlegroups.com>; Mon, 07 Jul 2025 13:46:25 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWjQzw97w/BJ+/0SJlkfxRIdW1OXGFisaVXTG/tzwsMXuLlN2+feNuyvUgSsKGo8e8cpje0cksJwRc=@googlegroups.com
X-Received: by 2002:a05:6402:3902:b0:60c:3f77:3f4e with SMTP id
 4fb4d7f45d1cf-6104680323cmr886164a12.22.1751921185468; Mon, 07 Jul 2025
 13:46:25 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1751862634.git.alx@kernel.org> <033bf00f1fcf808245ae150346019aa7b997ea11.1751862634.git.alx@kernel.org>
 <CAHk-=wh9Pqz07ne9iSt1_v0c14rkOGvF9AbEkaq1KnFhQD1SSA@mail.gmail.com> <20250707193521.GI1880847@ZenIV>
In-Reply-To: <20250707193521.GI1880847@ZenIV>
From: Linus Torvalds <torvalds@linux-foundation.org>
Date: Mon, 7 Jul 2025 13:46:08 -0700
X-Gmail-Original-Message-ID: <CAHk-=whcyA9kdWUc7HL39AhBoGzP90ntOzbBYpp=Z9M29bMPoA@mail.gmail.com>
X-Gm-Features: Ac12FXyTJdvBtSzuEgvvQf3FBl3I6foxcrWvzU70QsGHoB59-IiGkLMHShqelF0
Message-ID: <CAHk-=whcyA9kdWUc7HL39AhBoGzP90ntOzbBYpp=Z9M29bMPoA@mail.gmail.com>
Subject: Re: [RFC v3 3/7] mm: Use seprintf() instead of less ergonomic APIs
To: Al Viro <viro@zeniv.linux.org.uk>
Cc: Alejandro Colomar <alx@kernel.org>, linux-mm@kvack.org, linux-hardening@vger.kernel.org, 
	Kees Cook <kees@kernel.org>, Christopher Bazley <chris.bazley.wg14@gmail.com>, 
	shadow <~hallyn/shadow@lists.sr.ht>, linux-kernel@vger.kernel.org, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>, 
	Andrew Clayton <andrew@digital-domain.net>, Sven Schnelle <svens@linux.ibm.com>, 
	Heiko Carstens <hca@linux.ibm.com>, Tvrtko Ursulin <tvrtko.ursulin@igalia.com>, 
	"Huang, Ying" <ying.huang@intel.com>, Lee Schermerhorn <lee.schermerhorn@hp.com>, 
	Christophe JAILLET <christophe.jaillet@wanadoo.fr>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
	Chao Yu <chao.yu@oppo.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: torvalds@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=google header.b=CgAptjk1;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates
 2a00:1450:4864:20::636 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org;
       dara=pass header.i=@googlegroups.com
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

On Mon, 7 Jul 2025 at 12:35, Al Viro <viro@zeniv.linux.org.uk> wrote:
>
> Lifting struct membuf out of include/linux/regset.h, perhaps, and
> adding printf to the family?

membuf has its own problems. It doesn't remember the beginning of the
buffer, so while it's good for "fill in this buffer with streaming
data", it's pretty bad for "let's declare a buffer, fill it in, and
then use the buffer for something".

So with membuf, you can do that "fill this buffer" cleanly.

But you can't then do that "ok, it's filled, now flush it" - not
without passing in some other data (namely the original buffer data).

I don't exactly love "struct seq_buf" either - it's big and wasteful
because it has 64-bit sizes - but it at least *retains* the full
state, so you can do things like "print to this buffer" and "flush
this buffer" *without* passing around extra data.

              Linus

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CAHk-%3DwhcyA9kdWUc7HL39AhBoGzP90ntOzbBYpp%3DZ9M29bMPoA%40mail.gmail.com.
