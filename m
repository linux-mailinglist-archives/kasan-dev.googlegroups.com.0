Return-Path: <kasan-dev+bncBCP4ZTXNRIFBBAXCTDFQMGQEQ3RODXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 4B758D188FA
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Jan 2026 12:48:20 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id 2adb3069b0e04-59b6cf50eb2sf2983070e87.2
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Jan 2026 03:48:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768304899; cv=pass;
        d=google.com; s=arc-20240605;
        b=aFfqPgn2aI82jpNRpkPaIqtZXOiG4Czc3mk/DECD8ki9glzIFVIj0AyBwkhNtWcOUd
         LNElTq22IpzzNDEvHfhZcEZu/lc3JDgj+iIkQwyMCdUL+Yh5C2Sh5l7C/ES6w1gAPd6O
         rL+npTd5AMYW3XDsjYTK0HAIcjA02XwGIG6//Ygu5S0cs3sEXcCWCjtp53olcxyNWkUf
         Aawv+1sjKg78YOUnk4tJjDn7VFQxMrsISUtSEE9F1ZQZima1HLOwNALmJmmjwr+GzX/3
         kmhJ6tkqSl1mbFGgyuvdNEax661rHk/7bACepJGgvV5lFjrMCWVuwecPSv4ttGk7dwt9
         gx+Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=cznj69fXs4EWVufSBbQwMUBSLPQSQnrcgWCR60ndMI0=;
        fh=Pcaboq3/dI2E8ylisB+xhpzhsL4WJxBnVUcxhlnpFOQ=;
        b=b9MGAH7SOxU7fbZFiy+ZQlV65LxpKA2x/RSHFiJ5KpjCQFMQ0OzFtMQ0tKzru4cNlT
         nVN/eRiImteu8GWYl58aEvl/iFADP8w/nhrFcKeHs65X7a2rEpSpyhDk8llkLiX9RjM4
         i7u5Q80R5TMhyodSsKj0atsG/feg5KOD65gm2RAporbTYcn4lh+SHc3/ku6WWw/75iW2
         XuBku91PwKFaDgzgE5ArqHFBa5/9/1Sbx1Bdg5S8pMsBgyvoJUFzuG/nnopy0QSn5LA7
         pduSi6sRC4TTP5vs3rtoqrmLQhLO2j1ga3kbAsT40FNaknk2SM9RJU0/uLe6SktYdBfj
         P+Hg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=alien8 header.b=Xu0+QRmj;
       spf=pass (google.com: domain of bp@alien8.de designates 2a01:4f9:3051:3f93::2 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768304899; x=1768909699; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=cznj69fXs4EWVufSBbQwMUBSLPQSQnrcgWCR60ndMI0=;
        b=CcTjygTNtFKcsYEXGZq9TMVbkC2YzRgfBpu0SAf4wicmrcjIfrhbp/kpQDMg5US3US
         76qmvTzSOiuxNscdMmCe1m3WNUhhCj9kz/S58sDBI9Wi0uClvWxGCU42U/re0SZpVVU7
         UfeFgNflWcJRrXztdt2DVDhKi+GY72v/c/p2haPbqOZtnLXQy6kIe+/fhWOicgNeaQPv
         R2vRD+8Eo7bQWaIKyrtZq4yGVWBCuKiITFodseTTROTi0/+6Rs37m1E+1fzlLrEacblk
         /8gpfFr+3N8yzdhzoFe378krVGYmB+4J8uECWCNicN5ktWjTDOfJc/vX7Qu1Dk3zghPF
         qMNw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768304899; x=1768909699;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=cznj69fXs4EWVufSBbQwMUBSLPQSQnrcgWCR60ndMI0=;
        b=Dw5A3xUYvhUV05IqMI1QVcaJFkJKDbpmNql9aky/VYz1jia4W5z04h5PNO0KdqL3mN
         tSqPPBVl8aOXxzGkhf3PWu3OEKYjGL9+srI+MPUFscD7WbTenY2zUI9sQkazRnOQpREv
         QlzAKOz2fh8DACwDrIAV7/bm6kO8h+nKPqbwtKTevJRq1Zrn6CQMllmM5i5Ga081hnFa
         YiBqte3GRfwhLzJLFpXl2N096pKPImD1m6PZUT3YJUI7pU4wTvfulLWiIw1khbGUNges
         7BnYdd3rxiYxKmrrkEn1jFHkL9gDJSXqKe9NUKhuTz7t0/uEcZj9qnMFEJsr8TKcV53x
         I0gQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWKizfklNWKbv5eavxwhKSLvkfBfd4n7RHciudiBo2DVs7954K7qE0oDth17IjXXQHsdoMWnQ==@lfdr.de
X-Gm-Message-State: AOJu0YxGHcO+hqRh0fzWfCa//4rw1Xx/Kw1RhCJPDh+a8ahEf/0Ui82o
	cE2LSX4ZH6nWZIWjD84WPc74aHAwfXBfIR4sFk0WFn0XsHhJSrdSTKzc
X-Google-Smtp-Source: AGHT+IGfjch3i16kB+PChiKz81q+u+GCVJiYgosAy9U4O+cZ8kPCAzSNjIN1kez7XI9D9aNDNAed9w==
X-Received: by 2002:a05:6512:3ca4:b0:598:853e:bc9c with SMTP id 2adb3069b0e04-59b6ed134cdmr6824042e87.5.1768304899197;
        Tue, 13 Jan 2026 03:48:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FWckrrNZcfplJlg6StU1OQCfVMLqK4d0ilk3tqvQC1oA=="
Received: by 2002:a05:6512:3c9c:b0:598:f876:261c with SMTP id
 2adb3069b0e04-59b7bb44e3als1875559e87.0.-pod-prod-07-eu; Tue, 13 Jan 2026
 03:48:16 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWp77EXdlhve3ADJcc1joZZTuBD1nSAMyNM0HE9i6jccvc7sIplOkdDspq0rhShXUEzwN9vNegDXDg=@googlegroups.com
X-Received: by 2002:a05:6512:3b85:b0:59b:7b59:a4a3 with SMTP id 2adb3069b0e04-59b7b59a4fdmr5181676e87.17.1768304896359;
        Tue, 13 Jan 2026 03:48:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768304896; cv=none;
        d=google.com; s=arc-20240605;
        b=HTBJqU+lNqGL/gzsuJ5VNkN21FtPUCnea8v1HmpGq2/JcQKMiOduBwRqYe3FyLqf6G
         MduLnEjchLQluMBu3Eyt2VLLOBFyAfqdpLRDd5T21DgCqrvLoAAfJHv5wAhcD3DHBJUj
         tAO6JQotVBgECj14pEs4JqZFgFsmUGR4Awps8toTU8VZB4Ta3wKrNXbC0eF/hFsqUmes
         8iE2bzTrjsfEDBo/1abUKbikkWHFsIAfOASI4ESLSVjSUtW7jFC9uSYfGNo6jXeE7v6z
         StF9GLoShjgRkAr5EC4BTSyaMrOu6WnAGvf90R3wrZyF1yih6VfWR4XIkPl98xslkzsJ
         j6aQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=rTbY8atxjKRjBA0y7/TdrF1D3ojAC1i7Hfmy4BpGVjk=;
        fh=TZM41ALuxyD7pP9fPziDv8UDyHpXiVjm9cYoajF9HgI=;
        b=GwUwPcDxdVoFQLTrhZJgtE22aHXt32NP5oPXCJLScE7ebQ9sclvkJyz5Yd2OnWp8hD
         UiH1MvbWX8tRkSrUSFPIQHgdicpi+PtbB4aq9IRaV9Q1tEaRn12iAvS087LVrgq0EEze
         gGeFGM+Orrik2AQiZA++21fCptLZUbSCH5s1+OHg64htBwL9Qp/72pB4fEFOFE9AiVPd
         V58LZtsYyucApiSsVyGMdnZ9tjJeKwNKGfsscODCtqe37FEZmHhs2655778ouVNoCmYg
         LPfr6nq1rYa09xwvQqKraZpPMzGg9fZTbopune4gBXbA0oi3SsxF0pTOlFVP+sWxh9In
         Srug==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=alien8 header.b=Xu0+QRmj;
       spf=pass (google.com: domain of bp@alien8.de designates 2a01:4f9:3051:3f93::2 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
Received: from mail.alien8.de (mail.alien8.de. [2a01:4f9:3051:3f93::2])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-59b6f504593si281283e87.4.2026.01.13.03.48.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 13 Jan 2026 03:48:16 -0800 (PST)
Received-SPF: pass (google.com: domain of bp@alien8.de designates 2a01:4f9:3051:3f93::2 as permitted sender) client-ip=2a01:4f9:3051:3f93::2;
Received: from localhost (localhost.localdomain [127.0.0.1])
	by mail.alien8.de (SuperMail on ZX Spectrum 128k) with ESMTP id A7D7E40E01BB;
	Tue, 13 Jan 2026 11:48:15 +0000 (UTC)
X-Virus-Scanned: Debian amavisd-new at mail.alien8.de
Received: from mail.alien8.de ([127.0.0.1])
	by localhost (mail.alien8.de [127.0.0.1]) (amavisd-new, port 10026)
	with ESMTP id w9KlwacFOika; Tue, 13 Jan 2026 11:48:12 +0000 (UTC)
Received: from zn.tnic (pd953023b.dip0.t-ipconnect.de [217.83.2.59])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange ECDHE (P-256) server-signature ECDSA (P-256) server-digest SHA256)
	(No client certificate requested)
	by mail.alien8.de (SuperMail on ZX Spectrum 128k) with UTF8SMTPSA id 78B1A40E0194;
	Tue, 13 Jan 2026 11:47:06 +0000 (UTC)
Date: Tue, 13 Jan 2026 12:47:05 +0100
From: Borislav Petkov <bp@alien8.de>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Maciej Wieczor-Retman <m.wieczorretman@pm.me>, corbet@lwn.net,
	morbo@google.com, rppt@kernel.org, lorenzo.stoakes@oracle.com,
	ubizjak@gmail.com, mingo@redhat.com, vincenzo.frascino@arm.com,
	maciej.wieczor-retman@intel.com, maz@kernel.org,
	catalin.marinas@arm.com, yeoreum.yun@arm.com, will@kernel.org,
	jackmanb@google.com, samuel.holland@sifive.com, glider@google.com,
	osandov@fb.com, nsc@kernel.org, luto@kernel.org,
	jpoimboe@kernel.org, Liam.Howlett@oracle.com, kees@kernel.org,
	jan.kiszka@siemens.com, thomas.lendacky@amd.com,
	jeremy.linton@arm.com, dvyukov@google.com, axelrasmussen@google.com,
	leitao@debian.org, ryabinin.a.a@gmail.com, bigeasy@linutronix.de,
	peterz@infradead.org, mark.rutland@arm.com, urezki@gmail.com,
	brgerst@gmail.com, hpa@zytor.com, mhocko@suse.com,
	andreyknvl@gmail.com, weixugc@google.com, kbingham@kernel.org,
	vbabka@suse.cz, nathan@kernel.org, trintaeoitogc@gmail.com,
	samitolvanen@google.com, tglx@kernel.org, thuth@redhat.com,
	surenb@google.com, anshuman.khandual@arm.com, smostafa@google.com,
	yuanchu@google.com, ada.coupriediaz@arm.com,
	dave.hansen@linux.intel.com, kas@kernel.org,
	nick.desaulniers+lkml@gmail.com, david@kernel.org, ardb@kernel.org,
	justinstitt@google.com, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, kasan-dev@googlegroups.com,
	llvm@lists.linux.dev, linux-arm-kernel@lists.infradead.org,
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org,
	x86@kernel.org
Subject: Re: [PATCH v8 00/14] kasan: x86: arm64: KASAN tag-based mode for x86
Message-ID: <20260113114705.GJaWYwubl3yCqa1POx@fat_crate.local>
References: <cover.1768233085.git.m.wieczorretman@pm.me>
 <20260112102957.359c8de904b11dc23cffd575@linux-foundation.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20260112102957.359c8de904b11dc23cffd575@linux-foundation.org>
X-Original-Sender: bp@alien8.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@alien8.de header.s=alien8 header.b=Xu0+QRmj;       spf=pass
 (google.com: domain of bp@alien8.de designates 2a01:4f9:3051:3f93::2 as
 permitted sender) smtp.mailfrom=bp@alien8.de;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=alien8.de
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

On Mon, Jan 12, 2026 at 10:29:57AM -0800, Andrew Morton wrote:
> The review process seems to be proceeding OK so I'll add this to
> mm.git's mm-new branch, which is not included in linux-next.  I'll aim
> to hold it there for a week while people check the patches over and
> send out their acks (please).  Then I hope I can move it into mm.git's
> mm-unstable branch where it will receive linux-next exposure.

Yah, you can drop this one and take the next revision after all comments have
been addressed.

Thx.

-- 
Regards/Gruss,
    Boris.

https://people.kernel.org/tglx/notes-about-netiquette

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260113114705.GJaWYwubl3yCqa1POx%40fat_crate.local.
