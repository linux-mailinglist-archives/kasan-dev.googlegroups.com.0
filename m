Return-Path: <kasan-dev+bncBD22BAF5REGBBVFSSXFQMGQET5NH44A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id B1030D1536F
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 21:28:05 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id 2adb3069b0e04-59b70088327sf4889901e87.1
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 12:28:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768249685; cv=pass;
        d=google.com; s=arc-20240605;
        b=DgjwRiOG4DcdvziWrq1Z9mUAntEJ+3t3zCF6wqRqVNhkpp6OLJS/hZXd70TPpAIiBJ
         adl0Otc3mDTlomaJvSJjKBH6FzBg4mEtpMIpyXN7bChtyrJplJ4J+o5KUK4GReJwYj8Y
         6g6CCgs5IFzvsNrwTUQZZz1I6V/d+4Ei8+5gJBVW2ghDej3C6l9XDvil1xitUh43ddKS
         sn+S+tKdVL28JWJ2JnBaZq05WdKYklW4kcM5iiY8yjPS13E7SeogxEqqLWAGAOmFG63t
         RFgAjo70wm/Y7cVE/X3HL23/7Y4HDtYB8+HaqFLfrCiAVrqy9B8/K37Yxi+uych2kS7w
         JO2w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt
         :content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:sender:dkim-signature;
        bh=v+f8tuZDVYhycB8z6T8XztzYQ1Ve9S/9tlEd9ssJGaU=;
        fh=y5+LeuiocHHpSBCwAXsgComCLCvtknk2+9KNz9fWgak=;
        b=GhrR449yccDpWgUfiVq/h6M+B2qZkWIaJpRFs3Z2fIpekEllJdjeFUoHc01lo5w58e
         QybNcvCNatD4qklRSPykvDUKFCdvW9j+v+lypGj1WV3f+5dJZxL6GWtvBJFnRbReVlT4
         6C79ljIZAebmsQoIo7BLgAMBkBhoq2ZkCmSsBD53T0FLpJOI16IWfSH9S9qQYdIv7qaY
         lQqANuEqKxEzBy53EXv2ctOy46xvZXcvm2MVQghsbcCsvD6r1fj2bggPll8qKgNKlVvL
         uQ40Y/QIpjn++565S9042TTszf1tyYvTOFmi6j2brnTQDSkMwVYU7VdKbyllJjVo9px2
         0Q8w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=d1VAGuyS;
       spf=pass (google.com: domain of dave.hansen@intel.com designates 192.198.163.17 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768249685; x=1768854485; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=v+f8tuZDVYhycB8z6T8XztzYQ1Ve9S/9tlEd9ssJGaU=;
        b=KVBjbqEapACjjuIUE24E8RYncVTX78mZCYj9GAM73Hjz5Ec1eP852UkLKS92J7tSQl
         5MuQl73mZyUY4ZtdCtdbfsANpxTVnhPudaVJq5324pU3KbmfSmGZ3rI0X+2uZ514QZXl
         Flnf4YiwLmRiqzzdXzdGI4tTapN6bOEu0WDaAII6/vrsysaLpSaAtzoz7BezIeV+M4rc
         QZq4rFI1FxUNbMXOf02QTTgeGnvvyumDuyqyFz09d+R/qraH4HjVlgyf+icxtB+8y5We
         7DC5TuEZqBFVs/vFYOd6qqjoH5qStAgccXf1IdWH0cY1JNinI0dFOf/qzolRpsCa3FoQ
         NcBg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768249685; x=1768854485;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=v+f8tuZDVYhycB8z6T8XztzYQ1Ve9S/9tlEd9ssJGaU=;
        b=LSFrQJ/Yxl36DLwbAOY6c66LG8Amh40m0DEY/1SpRvizOad9BCKOHNFulS4vGxIDDL
         j5u7wJthuZ///KdqOjg59oQfIMf0Z+38jtD9N6b5KvjUkjCexY5HY1KoagiEUMcJjDDh
         GjW/O1BdAab2iL9OLmyAbmA0+WPs2crgbOl0M4LsRtp21BRdhGnSZhJxycA6happ7U6l
         pDjChOCORSpHUKtnsBsHfgKJdjJ4fs12y4otsbDdZpNAelwC+lGFpfZilT+TBEK5ADNy
         5jlCyQcbLLcoLcAFy+Lwwj+o8A27DXe5k7VRJHUbtUqe7DYNPfOoD2wuomOZdYGUIdHZ
         GrgA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXfkccI3Ucjg+p0YEtA9IVzdmX2aSJrbV6WUoBFcaDzYHx9K9IuFlH3BrbAnZD4IJeoKzG4Jg==@lfdr.de
X-Gm-Message-State: AOJu0Ywg1lfkF8Rev+cm5wYIvN1INM+8/zmfVN6odF835x+HwP4/g1T2
	nCF3mH3KdpBl4WYopYZB19gVA7QvZsUZw76Nzkf9ayQmCEiPLCthyv0X
X-Google-Smtp-Source: AGHT+IFrajxAXLaNTqgL8NaoAj8r+F27uZhB3W+zsAClJuPvFYUjYnqkdTKAO/R/fgO1Qhqh3OAKOQ==
X-Received: by 2002:a05:6512:2250:b0:598:ef92:d97 with SMTP id 2adb3069b0e04-59b6f046044mr6033869e87.43.1768249684884;
        Mon, 12 Jan 2026 12:28:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GvpFB2DOeKFmP90R1kBx2B6OOhhRUbGTVhiS50hetWtQ=="
Received: by 2002:a05:6512:4382:b0:59b:67d3:6052 with SMTP id
 2adb3069b0e04-59b67d365f9ls2007544e87.2.-pod-prod-03-eu; Mon, 12 Jan 2026
 12:28:02 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVBWNu5GcuzYJU4MbV2xtvbqAfzB8PKtEWubVzf1vV1eBd4ccC8mdYIgt8pKiJmr+gHa413sKZltIg=@googlegroups.com
X-Received: by 2002:a05:6512:a8a:b0:577:6e42:3718 with SMTP id 2adb3069b0e04-59b6ef0c29cmr7085679e87.7.1768249682136;
        Mon, 12 Jan 2026 12:28:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768249682; cv=none;
        d=google.com; s=arc-20240605;
        b=b3Co4YD0RPm7G2vSFHu+aZQpTgqopHmLGGRB04ANJnvY9EmPuSN16r4rpASBOY2aAU
         dtRYz63IocIa/FgpK3JxOKXpFdetioKGh/AyK1pHr1qHdyckWI/Xzqd/ZpCZA2W7xeAX
         TO9sDL9VlWK2uX6PknWOyhFGIKKJZmBO1YOII0TRMR/cb9rK/niO256QSbAnzWzZc/Tb
         WukU8/fv8zvDfTJl7+SggPiJr08T964qg1o+89pB4IxoctTXcX9CZKJrGUV5Mz7eaEBb
         yCGZeavx9/aUUgg8adbbKQHivFMpg3nOrSw9bDTF/wNpbiLzOjaDmVR4PIK2/fPHv92X
         Tz9Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:content-language
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=UB91Rsh68C1UNIlYIFLz5xmnPnEJwjihLfDwgTimA2g=;
        fh=hYo2A6rW4+Rmjc0MXf/7dx1LBivp1xA4VGwu/vm9Zh8=;
        b=bEIU92ed9c9oIMUXobQKvU/+9hs+Ssb4beF8/DiMw9jRnEurJMUxmECievow/srKfv
         GvM9Fa67AMFHtnzjSUKLvBdDXw57yK2FCilCwyRtWi7bc7ItJsebivN4DnIrghghf2uq
         lO+/f9u8RJMrRlC21h3ig0R9jyN5m8GApSictD5EH4lCTirslrW4zB2wwW/DsfXuQm/f
         wrhb8bM+7t3cE6xQYvjExqKelP3MKHIeBcjRLvn1CeyphcapUZy02Ww6G1OnVnD0HrSl
         ccnhrsDF4kc3NxkKHE6mV9itHvfN5Q6eGizPe8m/pNUd+x+3xgbf9vjadGdvg6ecJUIe
         hfpw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=d1VAGuyS;
       spf=pass (google.com: domain of dave.hansen@intel.com designates 192.198.163.17 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.17])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-59b6c0e891bsi341193e87.7.2026.01.12.12.28.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 12 Jan 2026 12:28:01 -0800 (PST)
Received-SPF: pass (google.com: domain of dave.hansen@intel.com designates 192.198.163.17 as permitted sender) client-ip=192.198.163.17;
X-CSE-ConnectionGUID: 4fm/9wzhTxmRvrk8PfXCaA==
X-CSE-MsgGUID: qwKRBj8aSji8KTkUg4+tqg==
X-IronPort-AV: E=McAfee;i="6800,10657,11669"; a="69443996"
X-IronPort-AV: E=Sophos;i="6.21,221,1763452800"; 
   d="scan'208";a="69443996"
Received: from fmviesa005.fm.intel.com ([10.60.135.145])
  by fmvoesa111.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 12 Jan 2026 12:27:58 -0800
X-CSE-ConnectionGUID: 3Fkudj2QRTePIWwm3VElwA==
X-CSE-MsgGUID: aaSqAWTbSpSfrO7GygXATQ==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.21,221,1763452800"; 
   d="scan'208";a="208659007"
Received: from vverma7-desk1.amr.corp.intel.com (HELO [10.125.110.123]) ([10.125.110.123])
  by fmviesa005-auth.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 12 Jan 2026 12:27:56 -0800
Message-ID: <9d78f71b-cbf1-4936-bc72-befa6d6bfe35@intel.com>
Date: Mon, 12 Jan 2026 12:27:54 -0800
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v8 00/14] kasan: x86: arm64: KASAN tag-based mode for x86
To: Andrew Morton <akpm@linux-foundation.org>,
 Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Cc: corbet@lwn.net, morbo@google.com, rppt@kernel.org,
 lorenzo.stoakes@oracle.com, ubizjak@gmail.com, mingo@redhat.com,
 vincenzo.frascino@arm.com, maciej.wieczor-retman@intel.com, maz@kernel.org,
 catalin.marinas@arm.com, yeoreum.yun@arm.com, will@kernel.org,
 jackmanb@google.com, samuel.holland@sifive.com, glider@google.com,
 osandov@fb.com, nsc@kernel.org, luto@kernel.org, jpoimboe@kernel.org,
 Liam.Howlett@oracle.com, kees@kernel.org, jan.kiszka@siemens.com,
 thomas.lendacky@amd.com, jeremy.linton@arm.com, dvyukov@google.com,
 axelrasmussen@google.com, leitao@debian.org, ryabinin.a.a@gmail.com,
 bigeasy@linutronix.de, peterz@infradead.org, mark.rutland@arm.com,
 urezki@gmail.com, brgerst@gmail.com, hpa@zytor.com, mhocko@suse.com,
 andreyknvl@gmail.com, weixugc@google.com, kbingham@kernel.org,
 vbabka@suse.cz, nathan@kernel.org, trintaeoitogc@gmail.com,
 samitolvanen@google.com, tglx@kernel.org, thuth@redhat.com,
 surenb@google.com, anshuman.khandual@arm.com, smostafa@google.com,
 yuanchu@google.com, ada.coupriediaz@arm.com, dave.hansen@linux.intel.com,
 kas@kernel.org, nick.desaulniers+lkml@gmail.com, david@kernel.org,
 bp@alien8.de, ardb@kernel.org, justinstitt@google.com,
 linux-kernel@vger.kernel.org, linux-mm@kvack.org,
 kasan-dev@googlegroups.com, llvm@lists.linux.dev,
 linux-arm-kernel@lists.infradead.org, linux-doc@vger.kernel.org,
 linux-kbuild@vger.kernel.org, x86@kernel.org
References: <cover.1768233085.git.m.wieczorretman@pm.me>
 <20260112102957.359c8de904b11dc23cffd575@linux-foundation.org>
From: Dave Hansen <dave.hansen@intel.com>
Content-Language: en-US
Autocrypt: addr=dave.hansen@intel.com; keydata=
 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
In-Reply-To: <20260112102957.359c8de904b11dc23cffd575@linux-foundation.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dave.hansen@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=d1VAGuyS;       spf=pass
 (google.com: domain of dave.hansen@intel.com designates 192.198.163.17 as
 permitted sender) smtp.mailfrom=dave.hansen@intel.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=intel.com
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

On 1/12/26 10:29, Andrew Morton wrote:
> On Mon, 12 Jan 2026 17:26:29 +0000 Maciej Wieczor-Retman <m.wieczorretman@pm.me> wrote:
>> The patchset aims to add a KASAN tag-based mode for the x86 architecture
>> with the help of the new CPU feature called Linear Address Masking
>> (LAM). Main improvement introduced by the series is 2x lower memory
>> usage compared to KASAN's generic mode, the only currently available
>> mode on x86. The tag based mode may also find errors that the generic
>> mode couldn't because of differences in how these modes operate.
> Well this is a hearty mixture of arm, x86 and MM.  I guess that means
> mm.git.
> 
> The review process seems to be proceeding OK so I'll add this to
> mm.git's mm-new branch, which is not included in linux-next.  I'll aim
> to hold it there for a week while people check the patches over and
> send out their acks (please).  Then I hope I can move it into mm.git's
> mm-unstable branch where it will receive linux-next exposure.

Yeah, it'll be good to get it some more testing exposure.

But, we definitely don't want it going upstream until it's more
thoroughly reviewed than it stands. Maciej, this would be a good time to
make sure you have a good idea who needs to review this and go rattle
some cages.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/9d78f71b-cbf1-4936-bc72-befa6d6bfe35%40intel.com.
