Return-Path: <kasan-dev+bncBCKMR55PYIGBBAP2VXBQMGQEAVEUZRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id BBD3FAFADBC
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Jul 2025 09:53:38 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id 5b1f17b1804b1-454b907e338sf13995225e9.1
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Jul 2025 00:53:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751874818; cv=pass;
        d=google.com; s=arc-20240605;
        b=MCEDwqPI0pPK/jIEiGFvknTxWGLd/o3CIOzFukDdVCO++8F0N9lU/Mezy7EK+wikMj
         kL7kx8LRAuV6ftHW+XTcuKqPQlkYQHERdlKz6CAteSn+/LEROMit9WcDPCkEbynd9yPR
         A/VDQueszB7clNPyXpk0UwCswxn1d1PDuOIgk9x+Z9ct/srJuMS3+o21dC8zQ0SB0VIb
         O3fUmxhT2lTW6RdiJiJsY3Cc9IVgo18oZyd5aMu4vKILQBEfQfq+z0SRe5aPoSe06QkT
         1egduemb9oyimmIELL6m17W+Wnkp/o6NEV74wTwWCg8ASh+JI07TRPA79mkj7tDAKR8V
         ETNQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=7CInShHYPOT6H/mBtrHACnLE0S75SnBHQkdxcdiwVDE=;
        fh=AFrHm0otb/sUjGaRQhw1rdxgT1Akfvxm+1TLwbSpJUU=;
        b=ep/EY4xOqD9bX43TRgGsqUDyPzD8VwgARVuLdpM8HHn71xUwC2x3KHdMfpyuqy06eH
         NdqRnTu2hr6E6YvihEaRpNnRQSO7hblvHfvEpoDLFWEjXH0qvXxNrU2dnXHl8JyYXWfz
         44uu9z7mOeUtJSqriAJmzYkNwT9AIYlj8pPebNprjmSN0kyUG2BsnPMI2/Qjd/LVurom
         RgI9Zf58hgKI8nnfgaqEopfuy6OAC7/vjIfhUquwOpXABUD4NlDpB1V/BUEpl+dWe7Xa
         wdMa5Udp8fY7JR2GqC+mmuOcUm3fxnwUD6/QoR9w9iD+pLkGhXd7230ThqY/UN0IRD7q
         CXew==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=google header.b=E+lt8LaN;
       spf=pass (google.com: domain of mhocko@suse.com designates 2a00:1450:4864:20::331 as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751874818; x=1752479618; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=7CInShHYPOT6H/mBtrHACnLE0S75SnBHQkdxcdiwVDE=;
        b=Fni8lJzotcM/RvtvuPUZWnZj5f/gqZFP3vemOGpfrJYVvH8dEB/vRVh6bsJeMJ2mIE
         28B6FyW5jgEdQSV6N+vYOgd2q8HCGTYkqYK5CAJqej2PysRgEDfua3TO5BK9OL0WirCv
         vKtSxtgw7DLDxh5kva6IzrJ4zD/Gl6W7ynNi89Lw8coRKKGrnXw480xnQGYNhPBveFYD
         1Fi4PhxAG4mjWW5Dx3euzBkjFwjFra0sVGuDG/okvLVRRzeXJHT2aLAROauUILTSnpdz
         qBUYyu9oBGIjDzakplKX2WCYPFOBm9coV1bDspmLVlKTpw3bQvv/Ju7jWvXCGpuBFR1C
         nKiA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751874818; x=1752479618;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=7CInShHYPOT6H/mBtrHACnLE0S75SnBHQkdxcdiwVDE=;
        b=R+BlwuRG26xKraCRLwiAEPbhulD19MQtsdwNzltHFBbVxxFZ4s5Xgw3QQ4DCgArbgt
         b4CK+pSSIZHi6+ECSB6AUbiHXiYIqssPmnxwQjtK/39LmbixvnaZL2j8/tXkbhFlBDrE
         VqYIvapT5WNIU75jN1r/7RuHw597JtCYySpJaUyHQKz7pkYXodnBOBtGPRkz9X9ydvmI
         5LG8FRAt1mkaq0UXc6XGffYDgmBfgI6DLQMQJOm62b5cEpJxmnK+HIdzSJIkQRaZ6h1s
         RDwtHXiZTxnrkQ+bVtCyDgYoRP0U/e9myKjNNBJzfE4oypom3WO5mTjFhY02KCGu3ZJ8
         cJkQ==
X-Forwarded-Encrypted: i=2; AJvYcCVhm4SQtCanPNUB70CaIvJRBbD5cBDUGZnZGQYklfIYPOTCyws9/n4jEjr/9cE6A6mrgGQ43A==@lfdr.de
X-Gm-Message-State: AOJu0YxFX5NmPdR2mPUUYgxJr4iGJJ79ZrBtqIgKsVbdGeaf9RabhuUk
	VgqAKwiCmWysvu2L00oaVPvdwiPfzrsDzHM2EnAlZVziSxEtpjHWGi3f
X-Google-Smtp-Source: AGHT+IHxIMqbGESor05AKTcu8RHinETY1Dt5ZcG5M17Yc9uHPO7VXxCC5SN/ojRlz/JgTGA55EHZBQ==
X-Received: by 2002:a05:6000:290a:b0:3a5:2949:6c38 with SMTP id ffacd0b85a97d-3b49aa82809mr5367638f8f.52.1751874817747;
        Mon, 07 Jul 2025 00:53:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdhhoABBIjwcVKquQ0e2iVtbuW6fb1yf75WZPO6U8O4LQ==
Received: by 2002:a05:6000:22ca:b0:3a4:eed9:7527 with SMTP id
 ffacd0b85a97d-3b49758c9c1ls1240807f8f.1.-pod-prod-02-eu; Mon, 07 Jul 2025
 00:53:33 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWbYSjHTwocV2MBQE6se9JIrc99YA0oOowE/s9k8xMztH09unDGA8cWBi2qTUj4NInqV7aG/L+wziw=@googlegroups.com
X-Received: by 2002:a05:6000:481c:b0:3a5:5270:c38f with SMTP id ffacd0b85a97d-3b49a959aa0mr4782514f8f.0.1751874813198;
        Mon, 07 Jul 2025 00:53:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751874813; cv=none;
        d=google.com; s=arc-20240605;
        b=HcFJ08kaIm+SzyX8D3sHrTKqTLoJGLFCLGqFxc9ahYG2hXnkQfMb4F8LCfgbyvZv2v
         Pg1r7sigVREbT29gLQhdDfH9regiJaPVyz3j+smQhukTpdTKKeielFa58k8sGDq0Whdc
         v2kJIHxt72eY7TC1USGcRaCn06psWSTvLDBE7k9/PwzDzZXW/8+QGZw3EOAYgcUXn8q3
         N6E25QiR6H3eezcG/FbcijO+8yqYmytiNGhAYeiNWCZouHwBTilWSb6iRzS3pkp1hOPI
         c4+UYp9yBqaPZQ+U3GcHgMVwjRGqGMYOlsigXP/LMEDZJ/UGHIvo6pbL8ws5JaDrWwv2
         Y3LQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=t1Okpmh1buK1WgbPFPnBrSgpONpB/cKbKxghn+7iu8A=;
        fh=2yAYkgZE4+6wyMNUOHFPKBejKs0gRg2P8pTK8VRfH98=;
        b=VLgdznB6OzR31C+pclbmahETuTAxNpP1w03h/XP4QRW0KQ5QvbtOinzKmWhbO7yYaY
         5qTZmoWKe7hPyYbsbYTLY1XE5tD5CpO+JGJxDTW1TlqEWgp/UGBo1HavA8ntr/Ip39aN
         Y1iB5SR3hH5tzMR9QqZ1koLE/lXPN1zRPfTEdrcuafdFHaXfRpIILk0/Jt51aX8wBpCq
         DmDq7K3iFUA5XchGrQzX0f1EwFGCh4E0od6FfTLTXS5lbfBJMMDp/xRSrdM3tUuvMuLN
         nL+T888aMA9swZpDRvuSgKDo+KFFCk6JBYq3sUwz8es5Du1Qw68Uc9AWJ68DuABKmgpE
         BOdg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=google header.b=E+lt8LaN;
       spf=pass (google.com: domain of mhocko@suse.com designates 2a00:1450:4864:20::331 as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x331.google.com (mail-wm1-x331.google.com. [2a00:1450:4864:20::331])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3b471b97360si244119f8f.8.2025.07.07.00.53.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Jul 2025 00:53:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of mhocko@suse.com designates 2a00:1450:4864:20::331 as permitted sender) client-ip=2a00:1450:4864:20::331;
Received: by mail-wm1-x331.google.com with SMTP id 5b1f17b1804b1-453647147c6so25617265e9.2
        for <kasan-dev@googlegroups.com>; Mon, 07 Jul 2025 00:53:33 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCV6fkMr43JV/rgqPFDoFUdQsrD0TU1Hd4bTm5GDZ9xG8zhurTw0EODFkH9oEp5n1CVvjkjXYR6p67M=@googlegroups.com
X-Gm-Gg: ASbGnctF7EtFZAL4XtzqYX+yXXC5NAE6p6nI0P7hGXnvbXYBO6LKeFON70rbZRPGBZD
	3f62xhdSfeDbiG2EWbEvSkMtvuUl/It6dDreE66kYFF3p7xGECrKbY3JOR8H6dDK8nAAdH8AC0W
	EsmcrSJ1CelKbFFbMpy8KEzAN/SVBTnXqoS5IFifSXq9FnQGKDsRzP/0ue5usXkA0Uy8TlXSd/r
	qY0WwrG4HPK97BXJ0MxUA9JqlbGH64kEhUgFhPs6+Bb+4H1DUp4WE/goZ212AGB/0WIOlusMe/m
	WUPZmVHURUWmKveYp4l17AqrDvrDVT2bnJd6RiFLASzVfhiWWSk1ed8u1pPkedPg6CuWlWr0Mcc
	=
X-Received: by 2002:a05:600c:5251:b0:43d:4686:5cfb with SMTP id 5b1f17b1804b1-454bb88a2f8mr64405185e9.27.1751874812666;
        Mon, 07 Jul 2025 00:53:32 -0700 (PDT)
Received: from localhost (109-81-17-167.rct.o2.cz. [109.81.17.167])
        by smtp.gmail.com with UTF8SMTPSA id 5b1f17b1804b1-454a998a731sm131477575e9.17.2025.07.07.00.53.32
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 07 Jul 2025 00:53:32 -0700 (PDT)
Date: Mon, 7 Jul 2025 09:53:31 +0200
From: "'Michal Hocko' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marco Elver <elver@google.com>
Cc: Alejandro Colomar <alx@kernel.org>, linux-mm@kvack.org,
	linux-hardening@vger.kernel.org, Kees Cook <kees@kernel.org>,
	Christopher Bazley <chris.bazley.wg14@gmail.com>,
	shadow <~hallyn/shadow@lists.sr.ht>, linux-kernel@vger.kernel.org,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Christoph Lameter <cl@linux.com>,
	David Rientjes <rientjes@google.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Harry Yoo <harry.yoo@oracle.com>,
	Andrew Clayton <andrew@digital-domain.net>,
	Jann Horn <jannh@google.com>,
	Linus Torvalds <torvalds@linux-foundation.org>
Subject: Re: [RFC v3 5/7] mm: Fix benign off-by-one bugs
Message-ID: <aGt8-4Dbgb-XmreV@tiehlicka>
References: <cover.1751862634.git.alx@kernel.org>
 <740755c1a888ae27de3f127c27bf925a91e9b264.1751862634.git.alx@kernel.org>
 <CANpmjNNQaAExO-E3-Z83MKfgavX4kb2C5GmefRZ0pXc5FPBazw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNNQaAExO-E3-Z83MKfgavX4kb2C5GmefRZ0pXc5FPBazw@mail.gmail.com>
X-Original-Sender: mhocko@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=google header.b=E+lt8LaN;       spf=pass
 (google.com: domain of mhocko@suse.com designates 2a00:1450:4864:20::331 as
 permitted sender) smtp.mailfrom=mhocko@suse.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Michal Hocko <mhocko@suse.com>
Reply-To: Michal Hocko <mhocko@suse.com>
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

On Mon 07-07-25 09:46:12, Marco Elver wrote:
> On Mon, 7 Jul 2025 at 07:06, Alejandro Colomar <alx@kernel.org> wrote:
> >
> > We were wasting a byte due to an off-by-one bug.  s[c]nprintf()
> > doesn't write more than $2 bytes including the null byte, so trying to
> > pass 'size-1' there is wasting one byte.  Now that we use seprintf(),
> > the situation isn't different: seprintf() will stop writing *before*
> > 'end' --that is, at most the terminating null byte will be written at
> > 'end-1'--.
> >
> > Fixes: bc8fbc5f305a (2021-02-26; "kfence: add test suite")
> > Fixes: 8ed691b02ade (2022-10-03; "kmsan: add tests for KMSAN")
> 
> Not sure about the Fixes - this means it's likely going to be
> backported to stable kernels, which is not appropriate. There's no
> functional problem, and these are tests only, so not worth the churn.

As long as there is no actual bug fixed then I believe those Fixes tags
are more confusing than actually helpful. And that applies to other
patches in this series as well.
-- 
Michal Hocko
SUSE Labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aGt8-4Dbgb-XmreV%40tiehlicka.
