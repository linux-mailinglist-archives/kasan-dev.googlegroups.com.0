Return-Path: <kasan-dev+bncBDDL3KWR4EBRB4EYXDCQMGQEWAUIYVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 15147B3732F
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Aug 2025 21:35:14 +0200 (CEST)
Received: by mail-il1-x13a.google.com with SMTP id e9e14a558f8ab-3efa61f3ab5sf11970305ab.3
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Aug 2025 12:35:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756236912; cv=pass;
        d=google.com; s=arc-20240605;
        b=OtbyT+uB98wHFVvdMgNHliD183x2Dh9phIeC2l4ePlaBQF8eYm6a3nOBwFit4qix/a
         2MqGMUf8K487AAe2BQe+am3pR4u4w/+A7llH8ji2T160WQx+egqBgSfYmMTpzK/lygbp
         odDDfHIR90FMmAS+ill3r+GBtaROFT8nlVQDKostF+mJ07dkDzLFB/Hyd8Hw2Fkq7Cdt
         31qnyPSLpp7cM9sCQBk1gP1Fq5gLy1lAELmWasILxGdEW4FQPa34ZsbCMi4pCo4U/1UR
         c+wBy/gBvb56g6C4qHoIYuJ+IT1nOT02cxPgcsSAOXHv3M6+EGHSXBfkJeAihqgmzSdN
         Iaew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=py89OfLJGEE1yljKJqfKiYrRMR8MrS+sSY334Vu5o5s=;
        fh=pknNJOW4sUIWTn9RPB6IE1OEeybqAcI9k9ncXgHrtbg=;
        b=SixJPPOyOyNVqeFT+6nHj04LDR9Yq2LKy2uV0yvPQooUa5KAWsuWFLL0mlAonQ3//h
         ZnIXwK/PEGEVwR0U/5w5e9poTAPk6N119zSz6zdU3u+vXytq6kDEdradC5QJSAhnMK+K
         PXgurx8t76+zE2KVYHfQBFT2enhiWlI7R0yup9ad0/d2KutWLn4BRrNK1zf94GQikD3h
         JkVWGZHD+xNfyVLDGjwQ3JqDl36lYjFJEiNa3KiyEbYqSVafeHBMDrhmIOU4fdLQjD0d
         RWWJ/b/3+dED9QYkhM04/61OWABlM0Je3sslzDXdpx7w+8JHY2NQFyaYrd7NqqDayyAf
         M4Kg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756236912; x=1756841712; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=py89OfLJGEE1yljKJqfKiYrRMR8MrS+sSY334Vu5o5s=;
        b=heEpqMPLapfYigR65QdL+1hK2JdL26U1NktX9z7JmJp3cVGpmcxdBZ2kNS5G5oVg3w
         fLzID/W1N1zE9lRJ0vpygBGZEaMvwFPlKxTDDlXLPqflQoKmrjp7QyzzvjGC0VFevX7T
         hOwoUoI7R8XN/389x6t1X8AAb6/IWFR5MtKT8o4OvK7Yuy+yEixI/cfuIo84BeEU5+vw
         5jbOZi0Qr6929PQRkhdLlB0HPXt8Q+pKr4ki5sIIc7YuVKtjfBhlTZqzMySJ59BTOxRw
         sPVy4rXXIA4yA/p3ynLgPH15duq2pLs+ixJ/xiwvxppp08LTDw41GVB9W3Ryby4jMRws
         DbOQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756236912; x=1756841712;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=py89OfLJGEE1yljKJqfKiYrRMR8MrS+sSY334Vu5o5s=;
        b=tCdB6KSHBuuX/8SlCe0ysJ5Hn6OxPkHlRMl6jz2cZ8AdCHAc6SX/DopwEGC+4TIw9m
         7coVAuks9FDWfRwd/q1oiZ45VBBhkcgoavHIX/E3IPPH9QsOKnlE2jITYRX+I5mdy2Gh
         VEErrVFhE1Dredak+jzOD38kN57ak9qZdCdyycWcOeAAj2y/xbPu5r0X2OWfEhUXiO6f
         abMdf23qQWh1uNds9WCs0ESgr5uuph+MAl9INkOjnGinfPQSV5d5SiB/2lqYAFOwgCZr
         7jjv0bY5ZVf8MolZnvT8bCyE4z2YzvJKp8CxLQBKUOXl6U303gny56NB/MJxFXqmgBnI
         AaeQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXEMejmBBIk5u1gnx+/A9gonQ3Y01lGLlziEvDKbQnJGDWPC9tfVtC6P1jNEwCxkwauEyt3lQ==@lfdr.de
X-Gm-Message-State: AOJu0Yw9EC7RLD68FtF/TUMxC/ynbxTKtfjyw/7sCRCAhZYvKSkynHqj
	y5eiv+1PY8xn6bM1VhoR44vO3IDkX08qrwJE2lAuv8aQQjhaKUn5BehU
X-Google-Smtp-Source: AGHT+IHJ7kCNTOvEcXXayP9nqSD1Ne4KPFJDSmQiL0I8AvPc+Wat6AV6EpqA6khUIHTaLnvVk4lsWg==
X-Received: by 2002:a05:6e02:2511:b0:3ee:f256:ad0f with SMTP id e9e14a558f8ab-3eef256aedbmr40302375ab.9.1756236912241;
        Tue, 26 Aug 2025 12:35:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcHLSAf8QBaeqaEBvV+GNuP2HV9riZD78x+S7fBZvFwJQ==
Received: by 2002:a05:6e02:4717:b0:3ea:468b:481f with SMTP id
 e9e14a558f8ab-3ea468b4915ls36778865ab.1.-pod-prod-05-us; Tue, 26 Aug 2025
 12:35:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXx24cY6n4Jonwz5ozrQ9XttMwbZQZj/d1WM7KVCsv239TCTc511VbB6PB+Ka2OPSSPoU4QvoDM9yU=@googlegroups.com
X-Received: by 2002:a05:6e02:1a89:b0:3eb:e9c6:8ee2 with SMTP id e9e14a558f8ab-3ebe9c69180mr139366455ab.26.1756236911071;
        Tue, 26 Aug 2025 12:35:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756236911; cv=none;
        d=google.com; s=arc-20240605;
        b=fQt9ceQw/RXtqy5F2LLHfRzo7WnYM4ldoa+wZutMEJP2fg+ZC17b4I52MwQWazELtR
         fSursU6rc+VMM4KyQOI6wfT9kqntxBPlWTX+TCW/xlVeb5KyocQTC7vdAUQ2DKcsyC52
         pb/huwhO5C2JfALvtFf0LLTPS6LbcQt77zJlXu+Zh0LShkBKw+O03iOwZ+BxoUl8y1jZ
         NF+uOvknKBQCp2F59o1nL5Xz9borIWsrW2XUfEeToox+Qj8h9mE2UMG+Qo7R8hX9bVPh
         sYn7r2yRuQJE0V8qLdxxetY0twb7Vp8rTygAlKW+A9wt6bWXcAGlOmV2P6qDlWUgvbwf
         8xHw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=FrT6fWaydhPGhOboMRkcmdWPYPAgiXGPSbIYcSJKONM=;
        fh=uTkSF0dNU1MYXKmorvv1rtxiUrLMnPQKHSlvrKIvDjg=;
        b=Amxjf/JmXIFAG3Euo4uAiuoD2r00DEyK1euYIwKD62htp3q8LUBQZYqttlNVn6PlQ+
         pyI4fH1ND82XnvQed/nzeJezQf539nObvfNwLdNmKYZitoMBPqGJGJAZ5JejpV8dGaGN
         3BFDZts/oUBldYWKiyNgXktV+sOEEjikzuxLtNT+fvLRpQjOcNpCRTxgHYUUqZwddDYQ
         p7pOxlVEW1MPxZze53go5kioMX6LTahWzZhqzbYTjSRFcjrrwsV8L3ZOhwurSjYMKvMo
         ITQj6K565VZiHWdc4CkY6kLUtWJgFL07ovkZRKJjjlSfLcUrqGu9jtlAF8+WZyJQi0XF
         Y2rw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3ea4c5693e2si5450945ab.2.2025.08.26.12.35.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 26 Aug 2025 12:35:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 68941437BD;
	Tue, 26 Aug 2025 19:35:10 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 8D065C4CEF1;
	Tue, 26 Aug 2025 19:34:57 +0000 (UTC)
Date: Tue, 26 Aug 2025 20:35:00 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Cc: sohil.mehta@intel.com, baohua@kernel.org, david@redhat.com,
	kbingham@kernel.org, weixugc@google.com, Liam.Howlett@oracle.com,
	alexandre.chartre@oracle.com, kas@kernel.org, mark.rutland@arm.com,
	trintaeoitogc@gmail.com, axelrasmussen@google.com,
	yuanchu@google.com, joey.gouly@arm.com, samitolvanen@google.com,
	joel.granados@kernel.org, graf@amazon.com,
	vincenzo.frascino@arm.com, kees@kernel.org, ardb@kernel.org,
	thiago.bauermann@linaro.org, glider@google.com, thuth@redhat.com,
	kuan-ying.lee@canonical.com, pasha.tatashin@soleen.com,
	nick.desaulniers+lkml@gmail.com, vbabka@suse.cz,
	kaleshsingh@google.com, justinstitt@google.com,
	alexander.shishkin@linux.intel.com, samuel.holland@sifive.com,
	dave.hansen@linux.intel.com, corbet@lwn.net, xin@zytor.com,
	dvyukov@google.com, tglx@linutronix.de,
	scott@os.amperecomputing.com, jason.andryuk@amd.com,
	morbo@google.com, nathan@kernel.org, lorenzo.stoakes@oracle.com,
	mingo@redhat.com, brgerst@gmail.com, kristina.martsenko@arm.com,
	bigeasy@linutronix.de, luto@kernel.org, jgross@suse.com,
	jpoimboe@kernel.org, urezki@gmail.com, mhocko@suse.com,
	ada.coupriediaz@arm.com, hpa@zytor.com, leitao@debian.org,
	peterz@infradead.org, wangkefeng.wang@huawei.com, surenb@google.com,
	ziy@nvidia.com, smostafa@google.com, ryabinin.a.a@gmail.com,
	ubizjak@gmail.com, jbohac@suse.cz, broonie@kernel.org,
	akpm@linux-foundation.org, guoweikang.kernel@gmail.com,
	rppt@kernel.org, pcc@google.com, jan.kiszka@siemens.com,
	nicolas.schier@linux.dev, will@kernel.org, andreyknvl@gmail.com,
	jhubbard@nvidia.com, bp@alien8.de, x86@kernel.org,
	linux-doc@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev,
	linux-kbuild@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org
Subject: Re: [PATCH v5 14/19] arm64: Unify software tag-based KASAN inline
 recovery path
Message-ID: <aK4MZGzTvJ8bBQvn@arm.com>
References: <cover.1756151769.git.maciej.wieczor-retman@intel.com>
 <eb073b008b547cf87722390cc94fe6e9d21c514e.1756151769.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <eb073b008b547cf87722390cc94fe6e9d21c514e.1756151769.git.maciej.wieczor-retman@intel.com>
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 172.234.252.31 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Mon, Aug 25, 2025 at 10:24:39PM +0200, Maciej Wieczor-Retman wrote:
> To avoid having a copy of a long comment explaining the intricacies of
> the inline KASAN recovery system and issues for every architecture that
> uses the software tag-based mode, a unified kasan_inline_recover()
> function was added.
> 
> Use kasan_inline_recover() in the kasan brk handler to cleanup the long
> comment, that's kept in the non-arch KASAN code.
> 
> Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>

Acked-by: Catalin Marinas <catalin.marinas@arm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aK4MZGzTvJ8bBQvn%40arm.com.
