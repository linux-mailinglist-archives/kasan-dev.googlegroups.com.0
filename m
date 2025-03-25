Return-Path: <kasan-dev+bncBDEKVJM7XAHRB6VIRO7QMGQEC2V4Q7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1140.google.com (mail-yw1-x1140.google.com [IPv6:2607:f8b0:4864:20::1140])
	by mail.lfdr.de (Postfix) with ESMTPS id E451CA70603
	for <lists+kasan-dev@lfdr.de>; Tue, 25 Mar 2025 17:06:20 +0100 (CET)
Received: by mail-yw1-x1140.google.com with SMTP id 00721157ae682-6fef68b65c7sf83801287b3.2
        for <lists+kasan-dev@lfdr.de>; Tue, 25 Mar 2025 09:06:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1742918779; cv=pass;
        d=google.com; s=arc-20240605;
        b=GPzaMHKJ3J7IhPExSd+nR+SPod4nRKx9WD9we7GJegjUOKebVAjXrCOMJ7FhJfyXEf
         Y4jBBfen6ydRsUILahJ1W76kpEe86Qxz4PVHlqxVyqTBjiKIQ4o7oc1cObfsRkJhXrCo
         LEN4yBjpt1t1Eo3DSsh8hksewf70l1Q9YQSms1QDuY4+3kv4xx6An/odPRD+HrwDNvj7
         whQHaXa20zGRBH89oKcOczRODuV5DzcqRdRun2jOlVKlGQma/ALju1JW7Zvi6BUU8lJD
         CIReV30L9KxiWteTg8bwqbo3jcgzahhX31gnLkg2GyiHh6Mml9n7jSCJa8F7LQEtAblj
         WKtw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:references:in-reply-to
         :message-id:cc:to:from:date:mime-version:feedback-id:sender
         :dkim-signature;
        bh=kltlG/cdnQ8eoguXkdpPAiBIvcXJvu6vMn1hUqiGFFA=;
        fh=BU3c6Bei/GQuGf7kv5nD8WKOZO9kCHP/HRzAkp9pQ6o=;
        b=fjD/skY4+xO1HAYoyyUhEfft2qBL9k42GEfpjuFbMvMB88SYy3qz4AzXzz5DrmvN3f
         hiknrZjQ3iGjV62/hSHaAmcJ5N2aRR6lb3kXHHLKfsShWYKUIkfgmAR+J9aODElfnetF
         XoS9tUMUaOu2UIvgj3qz3lDqWjf0+HYzQRDw2e8oCtUArxaQvb3O6NIvQzxR+XzscGNe
         +NMuxweei1DhVA+5jPE7ygxzMiqVJCu/m66mgGW02/7MjYZOIC/DyElwiESf+JsziyQr
         hqyXArNZ/2SeAjhLBO7Ij7wyBD0T1VuevEEBDi6+4f4yf/IDpPTnQpfGOtRdnGVJeSJ9
         EnSA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@arndb.de header.s=fm1 header.b=esKtqLEC;
       dkim=pass header.i=@messagingengine.com header.s=fm2 header.b=mBJCjyD8;
       spf=pass (google.com: domain of arnd@arndb.de designates 202.12.124.153 as permitted sender) smtp.mailfrom=arnd@arndb.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arndb.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1742918779; x=1743523579; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:subject:references:in-reply-to:message-id:cc:to
         :from:date:mime-version:feedback-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=kltlG/cdnQ8eoguXkdpPAiBIvcXJvu6vMn1hUqiGFFA=;
        b=W0MemPhC7PKafb7/EGxkkRR9rZCm3ujjVWpFbBbbOdO4A0ksfRkAglWsw5SAIi4IzS
         l/TRE/voIRJMWXl2STFiTMCEQUDCPYKx4IjAxHQM0NFN4yKWmmeS9dV5/CCt3+WbpIrn
         QWNT9ajGQIrXFArvil6+6yvbiSw82iGnvxD6eBcfXFkCcY3XTJRGSw0IGCbj99roiiRh
         GuVIiZqKngFdporR0To318FVtgEdAoQDBHze9yriJa0gOJ8cRCBZI9WDF553AGl3urEA
         e6FAZzqLckwOq+RZjaG+X9Q9b/4M02nyUdtR8TZNNVCWj/+LonJ9EB9D8ruz4oAK0sDp
         XYkQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1742918779; x=1743523579;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:subject
         :references:in-reply-to:message-id:cc:to:from:date:mime-version
         :feedback-id:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=kltlG/cdnQ8eoguXkdpPAiBIvcXJvu6vMn1hUqiGFFA=;
        b=ZSN6hMSOy39WrhLINZefziYKum4UpdugODzVYB/EZUOaJJHK9FCAGZ8ox6vALkNQ6E
         vki+E+PT+tHTx33C/a6rEaW+b5JJNFm2MFeFPDl/fgT5FN+46Gd+PQDsGqBfapFoiNVX
         UDEniPhhBPvKK5ca1uFFbgO4nNS9SPEKNrqb+3HwFM7XPTjhYnlngodj4QoNxY29f8yX
         bq+Z0kfj/uYQtqvSxddFjdDvuLHCF7r08R7dgXOn3Rt+zS8u5vMjPwB9/gCjwVIIt6gV
         xX0hC53r8lpBRyVRoOGGwC5qPeIyQt1C8N/LwEDfZnedMfZUFKt3m+XHpmQVK3Os1o7E
         zvuA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWIN4ZW8XHJJnI+pvP0r+WTUvpEgZZ7NM1brucBUXKLGO6Nt/7q7euqSGRXu03x2X+yCVPiyA==@lfdr.de
X-Gm-Message-State: AOJu0YzhNON5Cf3yovOI2h6vIURsCReJar6tZuEPOGLBoc/H4jWsxYWp
	+UBZ8f4y3zR6eYjZvF9wr4oXCdIYlTNVSRoUbJqMg4ve/JC/eDF8
X-Google-Smtp-Source: AGHT+IFxHcBwfhGCQSN/B6rRljY5F8NQps9o0oWeiAoe3FvWu63sGcLrZjHJyTdXEIDMIvQ5tVSiyw==
X-Received: by 2002:a05:6902:cc7:b0:e63:ddbb:a742 with SMTP id 3f1490d57ef6-e66a4d2e32fmr22927451276.2.1742918779213;
        Tue, 25 Mar 2025 09:06:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAJAMLCTXDb51qlKIIB2UovMw4eb5iq940ZJ7A3bslVCNw==
Received: by 2002:a25:268b:0:b0:e69:2fc1:9b40 with SMTP id 3f1490d57ef6-e692fc1b76bls13050276.2.-pod-prod-05-us;
 Tue, 25 Mar 2025 09:06:17 -0700 (PDT)
X-Received: by 2002:a05:6902:2382:b0:e60:93c5:9b1f with SMTP id 3f1490d57ef6-e66a4d2e0c5mr21796715276.6.1742918777675;
        Tue, 25 Mar 2025 09:06:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1742918777; cv=none;
        d=google.com; s=arc-20240605;
        b=NEJFpGijSzNTzeJ19Qj75oGIVNpVse5Nvp23h2AXABVyNPV7QfuyZO4El24TzpmAWE
         IqIeKdrsfjN+BuvNJBuTu6Vzns5V4CHMq8cPTPYPprM1NyF7O8U8kLeK7kBsCNRGK/7B
         uiwy+SlW9fFLVoAUZe/WMqayktImT6z8XL3i0Z+93aVqnMUvW/r/Wx/M4j8REfISpvsb
         R62DltIS17s0lQfEMb5AdVAWLROnDnA6erFcj6sTxjbjGNvxbylbylhk+QsEvdyM3jlP
         RLb1b2IoG95ghd2WnqyYYf4ztVJ7369RX6cb/7iBOVhcNdDxE9aJrS271Y5bIN+wViA/
         E+kw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:subject:references:in-reply-to:message-id
         :cc:to:from:date:mime-version:feedback-id:dkim-signature
         :dkim-signature;
        bh=i5gIEhSWhDc/CD1KGDEUUBNtkR8QlRiEolUuUnkGdoo=;
        fh=vhypyy0DuQjVnzIjRB76uSqYzwCNgIbijK9Wi0KEQEg=;
        b=VmtJI4pvKeW56ZzB2Jen1ntmRYh0rVYZCvPC0Af2K0F5A4e+RgOS5a6OFfwPjQUmkN
         bvMQXKLoMbU58Oo1et+qI1x+m5zqpJctzvrIH2T+0Snyk5Dt0WMF/76qcE0kwtIv4Gx3
         /4BCMIt4kihQLycfm181vcseRt39/xCFLfG/4OqdvPm7d+B+5Bv5GncDdYJmfu8X6+VE
         nc+xFni3UnJZPhDiMKCR6PhxJEXptF3lfYULRDufHOTpxYRHAhhwJbiCEj3afsznh0XE
         8pCYfWs4d8G/qzQLhz1dNm9WF59SVNOITdXPHzfcYD78sdfcqhZJKWZ8JMv5srr2/viM
         PODw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@arndb.de header.s=fm1 header.b=esKtqLEC;
       dkim=pass header.i=@messagingengine.com header.s=fm2 header.b=mBJCjyD8;
       spf=pass (google.com: domain of arnd@arndb.de designates 202.12.124.153 as permitted sender) smtp.mailfrom=arnd@arndb.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arndb.de
Received: from fhigh-b2-smtp.messagingengine.com (fhigh-b2-smtp.messagingengine.com. [202.12.124.153])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e66a53fc166si409875276.4.2025.03.25.09.06.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 25 Mar 2025 09:06:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of arnd@arndb.de designates 202.12.124.153 as permitted sender) client-ip=202.12.124.153;
Received: from phl-compute-07.internal (phl-compute-07.phl.internal [10.202.2.47])
	by mailfhigh.stl.internal (Postfix) with ESMTP id CDF3B2540092;
	Tue, 25 Mar 2025 12:06:16 -0400 (EDT)
Received: from phl-imap-11 ([10.202.2.101])
  by phl-compute-07.internal (MEProxy); Tue, 25 Mar 2025 12:06:16 -0400
X-ME-Sender: <xms:eNTiZwQlPft4XSGRBXtVoJhgFD-vKRjCjv4oPdAhBskETnzprfZGtw>
    <xme:eNTiZ9x28MeQ3cTw5PO5lrE7uhedBL9lD7oIfOxTU8hc6L2AUwszexsSBF4-LT1Y9
    AxkH4qVgslJrAbGEv8>
X-ME-Proxy-Cause: gggruggvucftvghtrhhoucdtuddrgeefvddrtddtgdduieeftdekucetufdoteggodetrf
    dotffvucfrrhhofhhilhgvmecuhfgrshhtofgrihhlpdggtfgfnhhsuhgsshgtrhhisggv
    pdfurfetoffkrfgpnffqhgenuceurghilhhouhhtmecufedttdenucesvcftvggtihhpih
    gvnhhtshculddquddttddmnecujfgurhepofggfffhvfevkfgjfhfutgfgsehtjeertder
    tddtnecuhfhrohhmpedftehrnhguuceuvghrghhmrghnnhdfuceorghrnhgusegrrhhnug
    gsrdguvgeqnecuggftrfgrthhtvghrnhephfdthfdvtdefhedukeetgefggffhjeeggeet
    fefggfevudegudevledvkefhvdeinecuvehluhhsthgvrhfuihiivgeptdenucfrrghrrg
    hmpehmrghilhhfrhhomheprghrnhgusegrrhhnuggsrdguvgdpnhgspghrtghpthhtohep
    iedpmhhouggvpehsmhhtphhouhhtpdhrtghpthhtohepughvhihukhhovhesghhoohhglh
    gvrdgtohhmpdhrtghpthhtohepvghlvhgvrhesghhoohhglhgvrdgtohhmpdhrtghpthht
    ohepjhgrnhhnhhesghhoohhglhgvrdgtohhmpdhrtghpthhtohepkhgrshgrnhdquggvvh
    esghhoohhglhgvghhrohhuphhsrdgtohhmpdhrtghpthhtoheplhhinhhugidqrghrtghh
    sehvghgvrhdrkhgvrhhnvghlrdhorhhgpdhrtghpthhtoheplhhinhhugidqkhgvrhhnvg
    hlsehvghgvrhdrkhgvrhhnvghlrdhorhhg
X-ME-Proxy: <xmx:eNTiZ92bXH6QFbxQO7HBGMa0g4GARgz_nwJE28LhKcPrr6RmFCwNAw>
    <xmx:eNTiZ0BXFpzb0QGtoIFoaLaggqk1VxeUOnLPOsKLZn4NPKnEZxM-Aw>
    <xmx:eNTiZ5hqKrPp0M7VQwCUhrF7Pxau2BZKq4SuyuPhjyxp0dwGmUgcCw>
    <xmx:eNTiZwqP2vlLz9nuyx9gTFNWMhpW2MI75QxDR3nefI3irdpX1BxA7g>
    <xmx:eNTiZ3YkwhbNrX_V5IcNwWphY-Fxw97ZuQL3WccceM9V_GtiEYOel2E2>
Feedback-ID: i56a14606:Fastmail
Received: by mailuser.phl.internal (Postfix, from userid 501)
	id 61E852220072; Tue, 25 Mar 2025 12:06:16 -0400 (EDT)
X-Mailer: MessagingEngine.com Webmail Interface
MIME-Version: 1.0
X-ThreadId: T022a60d36d02d9f7
Date: Tue, 25 Mar 2025 17:05:55 +0100
From: "Arnd Bergmann" <arnd@arndb.de>
To: "Jann Horn" <jannh@google.com>, "Marco Elver" <elver@google.com>,
 "Dmitry Vyukov" <dvyukov@google.com>
Cc: kasan-dev@googlegroups.com, Linux-Arch <linux-arch@vger.kernel.org>,
 linux-kernel@vger.kernel.org
Message-Id: <26df580c-b2cc-4bb0-b15b-4e9b74897ff0@app.fastmail.com>
In-Reply-To: <20250325-kcsan-rwonce-v1-1-36b3833a66ae@google.com>
References: <20250325-kcsan-rwonce-v1-1-36b3833a66ae@google.com>
Subject: Re: [PATCH] rwonce: handle KCSAN like KASAN in read_word_at_a_time()
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: arnd@arndb.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@arndb.de header.s=fm1 header.b=esKtqLEC;       dkim=pass
 header.i=@messagingengine.com header.s=fm2 header.b=mBJCjyD8;       spf=pass
 (google.com: domain of arnd@arndb.de designates 202.12.124.153 as permitted
 sender) smtp.mailfrom=arnd@arndb.de;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=arndb.de
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

On Tue, Mar 25, 2025, at 17:01, Jann Horn wrote:
> Fixes: dfd402a4c4ba ("kcsan: Add Kernel Concurrency Sanitizer infrastructure")
> Signed-off-by: Jann Horn <jannh@google.com>

Acked-by: Arnd Bergmann <arnd@arndb.de>

> ---
> This is a low-priority fix. I've never actually hit this issue with
> upstream KCSAN.
> (I only noticed it because I... err... hooked up KASAN to the KCSAN
> hooks. Long story.)
>
> I'm not sure if this should go through Arnd's tree (because it's in
> rwonce.h) or Marco's (because it's a KCSAN thing).
> Going through Marco's tree (after getting an Ack from Arnd) might
> work a little better for me, I may or may not have more KCSAN patches
> in the future.

I agree it's easier if Marco takes it through his tree, as this
is something I rarely touch.

If Marco has nothing else pending for 6.15, I can take it though.

       Arnd

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/26df580c-b2cc-4bb0-b15b-4e9b74897ff0%40app.fastmail.com.
