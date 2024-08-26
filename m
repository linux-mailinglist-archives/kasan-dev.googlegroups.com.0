Return-Path: <kasan-dev+bncBDXYDPH3S4OBBNGKWO3AMGQEXGB2M2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id AFD5B95FA9A
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Aug 2024 22:27:34 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id 38308e7fff4ca-2f3f1bbe2e2sf33844011fa.0
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Aug 2024 13:27:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1724704054; cv=pass;
        d=google.com; s=arc-20160816;
        b=badTG7FsYt0lUAmX4eajtGiL1l0bJ7PA2Wpjyh9YoWTsvjm4RL50AAwyn3Zggcuzzw
         rxMv8XiasHApTx4zbNxzT7WlAmKZJt0HBxm2d9L4BP/bkuKcVjid3eQgfIvxW7l3a2Mq
         eJAr3n0LEHZMa7n+43a/4OJL0LwCAiexW5QH9Oee/2o9JK2oIC7QJsuBGHIHwYid5nV+
         5DUn1cotD35InkgVFT3rT5Hchp5zNUc4a1OBR4jFslcbf5LSfPoHwIjjPLP6O3uF5P1Z
         /SQ1Wl8jpMbv9vTt8mvGbcrFEjufnb/rOzU+LHxzi4E/ZxNO8x6pp0vvv7iopf2HITk2
         i2kg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:autocrypt:from:references:cc:to:content-language
         :subject:user-agent:mime-version:date:message-id:sender
         :dkim-signature;
        bh=QKM1SHzZr2LW/Xpcwgts01Y4ifA/zh+Uxt1wbdMAycA=;
        fh=J2yyWEdymWrwTg5u82VgPOuaskHU5vx0gpqt/aShOkc=;
        b=I9K/op+18fGYWZeWUeYSnQQV83ARx9Dei7F6ESl+g0fSTbATcZDaipYA7BWDOQfWQ1
         Mvk56SckQQlMMR6+YlsLVdhZeev9pR7/G0fNz7aniSjXGPEFiIBer+ULpqfhPeLKlbWW
         aGM5oBLZDvHDqa/qE75A0huS5q4xr9e19lQIkXmfJ0vnOiMTfv82uWsXA9Z80D5YT09S
         e2twxOwoutUF6Qx26OktxdbxJ/Sadoa1KPrtm3u1EipsDaDhE0R5fmuz+lefDQF6C4Z2
         cNyK9yVgHrh0JVxYmtdVsql4lMBzMFVCrJFKVXOd5UhpcYlLYPMe8IzSfzpu97OrWNiA
         5JEQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=xrz5hmbG;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=xrz5hmbG;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1724704054; x=1725308854; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:autocrypt
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=QKM1SHzZr2LW/Xpcwgts01Y4ifA/zh+Uxt1wbdMAycA=;
        b=WypKG/oYqRKOmDi504j72TfQcnmFxAclsnKrwm/XaBP2zcmghAn3+zMjGKrfeDCIIL
         6ZpSERIeIUonohpXFQ0S3/w6JvH5kZO28t3X4WZ3G4EVk3unlX+6WK2fNPQEE5A0lKY8
         ZHfLS+snBjrZbRS0OGPM8YigMjmLkAH8B3DyPkF3Vt1H7sdiYsJyEc914erfNuC/7TAG
         sYMT3Oa6r7TP5+RdJ0yl7aUCadcv5DCYDzDb8FvwW3EZTDNwh2c96It7jinZRlDLOAY2
         7675V05R40RZ3PW04F2nJj6YcvGQ9aO+2O3eHtif+SMuwmq0MYDOBJr+nJzCOjFp97KY
         CdZg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1724704054; x=1725308854;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=QKM1SHzZr2LW/Xpcwgts01Y4ifA/zh+Uxt1wbdMAycA=;
        b=Exb/Sxrb6ouant3H7oQgMoBQvHh0Y/o8ubqx9/1JVIDAZIaFmOeHk1XLzPWHcrmnT/
         lRhUGfDsUeyOHGGsOhdTEgujpHwHqy7iFhuKhQtYQtcPzp2C7S7z/hq6yzqnkckWPy+N
         KcyDSaQQVfxkkQ3xHRij9sIx/mZe1lvoBlbtsbd397dFMv3mERPSTQt0K0LRb+OrQJCY
         p6bu/HlNWCY7RX+LVSnUq12XQ64GFSOSZ1K2foz4zmFsIwFbNMmA3BgfsYZhU051DlH5
         x0cTh+ZPDrRMUY+rR46OAaEMRJrlq4XK28/UuG+mXFdRV8yPQXzVCPcRHqmpgvEo48Yo
         e5Kw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXPVeBCnmRq0d6Wq8TdD9hYWaDD5vcEQPMaG1s0LHKnOpFL3TsQ2gdYeBXH+7SPmhv0+K3KxA==@lfdr.de
X-Gm-Message-State: AOJu0Yw69A0lrCf+e1Zb8QWPtG1aC4LSxe+f7e6JuY5GH4vEbrbs00+D
	bVYL6ia9eyjb2BfN4PHGMqhI10j/zbfFM/phwbqjf/QH/PSkSoGP
X-Google-Smtp-Source: AGHT+IEPgMliLolyr0tzqhic+vyy+3IpUkbn7HPluWSxDQBKYYQjfGoYQPZwJadMZ2niiKTW9XlU/A==
X-Received: by 2002:a05:651c:54e:b0:2ef:2c0f:283e with SMTP id 38308e7fff4ca-2f514a2fd6amr4914741fa.12.1724704052695;
        Mon, 26 Aug 2024 13:27:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:22c6:0:b0:2f3:f220:2807 with SMTP id 38308e7fff4ca-2f402fab7d5ls15510631fa.0.-pod-prod-07-eu;
 Mon, 26 Aug 2024 13:27:30 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUyP/3M24aWibzlRItyTGAbudYFQPw/OHPbtXAFLELjxZSXxeiadnEdQk/qSlFw5tBenvg1SrPzb8M=@googlegroups.com
X-Received: by 2002:a2e:a58a:0:b0:2f3:e2f0:f7e with SMTP id 38308e7fff4ca-2f514a3007bmr4722541fa.19.1724704050396;
        Mon, 26 Aug 2024 13:27:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1724704050; cv=none;
        d=google.com; s=arc-20240605;
        b=du6SWxDQ06PM4w/Mer7ROJOh2z7bwjyK+eAPq6gw47RwRq3+oLFY1kAB/rnE66Vh6A
         MPd8TkUw1nu+3mhtsVAIHsfoB0TNMFVzfm9l+tDEuDpkKEqER57nBoyhi41sPMNB35NC
         8hbDgpzn7YbDiK+0QZxwdS2BLE7kTTblfhuVMfNmqderjvycUP4DDFY6aHU+9kq4H0K2
         IR0dbna+YViTm3R6tOyjOS7WnQELjrlFtwoWdqfTwDRlkjElpEstP/08BX4rEfBW8ill
         IWOu2g9F+xe6G5aiKr97VRGLlUMpmGt1c7dThRJprunTkXPyaixEsaYDHMIbmPQUsWWj
         e1Vw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=tKyaYIvThFI4rSLLMtBRxA0iwJL7PQ25bt4xJ6byBIo=;
        fh=NA0v129B4YZwHuxGJEbylVmxyHcWIUf2tgWlmboaKXQ=;
        b=MXmDahiHvpzR1/e2ZXQcaFNUT5+w5TkOoP6pRN1UAosiYQKSttSi++e2depd5CZBJi
         5i86vwXqLRC5x0gQEDva7kjOAFxQVyeAKnskRfC2Vf3V3Ym9wQz4sci4gZ8ExAgI1Z8l
         Ivdg/YrD1ugyc9LvU3abrAIOLqNnrWZESWepl6fGq/mwXbn8HKIJs+CeodBMYxrJs6Hk
         qujer7gD+rZb8c9CT0L1JtEVETp8QXtzJVuLHHl71ywitt+Ron1ypDhIR78QwaCNP6WQ
         FWDiw9FT1VBshR9kO9zcYfTA/95fSmAiJFg98lN522UE48PzL71TtsGIOqoGVG50Ptg+
         ASNA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=xrz5hmbG;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=xrz5hmbG;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-2f4048c5d91si2346691fa.6.2024.08.26.13.27.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 26 Aug 2024 13:27:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 6B1511F8AE;
	Mon, 26 Aug 2024 20:27:29 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 50E2713724;
	Mon, 26 Aug 2024 20:27:29 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id n7gYEzHlzGZkRwAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Mon, 26 Aug 2024 20:27:29 +0000
Message-ID: <4fbe9507-13b9-4af5-88c3-63379835f386@suse.cz>
Date: Mon, 26 Aug 2024 22:27:29 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [linux-next:master] [slub] 3a34e8ea62:
 BUG:KASAN:slab-use-after-free_in_kmem_cache_rcu_uaf
Content-Language: en-US
To: Jann Horn <jannh@google.com>, kernel test robot <oliver.sang@intel.com>
Cc: oe-lkp@lists.linux.dev, lkp@intel.com,
 Linux Memory Management List <linux-mm@kvack.org>,
 Andrey Konovalov <andreyknvl@gmail.com>, Marco Elver <elver@google.com>,
 kasan-dev@googlegroups.com
References: <202408251741.4ce3b34e-oliver.sang@intel.com>
 <CAG48ez1o2GvYuMxox5HngG57CFcZYVJ02PxF_20ELN7e29epCA@mail.gmail.com>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 EP+ylKVEKb0Q2A==
In-Reply-To: <CAG48ez1o2GvYuMxox5HngG57CFcZYVJ02PxF_20ELN7e29epCA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Spam-Score: -4.30
X-Spamd-Result: default: False [-4.30 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	MIME_TRACE(0.00)[0:+];
	ARC_NA(0.00)[];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	FREEMAIL_CC(0.00)[lists.linux.dev,intel.com,kvack.org,gmail.com,google.com,googlegroups.com];
	FUZZY_BLOCKED(0.00)[rspamd.com];
	RCVD_TLS_ALL(0.00)[];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	TO_DN_SOME(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	RCPT_COUNT_SEVEN(0.00)[8];
	MID_RHS_MATCH_FROM(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:mid,01.org:url,imap1.dmz-prg2.suse.org:helo,intel.com:email]
X-Spam-Flag: NO
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=xrz5hmbG;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=xrz5hmbG;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2
 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 8/26/24 22:18, Jann Horn wrote:
> Hi!
>=20
> On Sun, Aug 25, 2024 at 11:45=E2=80=AFAM kernel test robot
> <oliver.sang@intel.com> wrote:
>> Hello,
>>
>> kernel test robot noticed "BUG:KASAN:slab-use-after-free_in_kmem_cache_r=
cu_uaf" on:
>>
>> commit: 3a34e8ea62cdeba64a66fa4489059c59ba4ec285 ("slub: Introduce CONFI=
G_SLUB_RCU_DEBUG")
>> https://git.kernel.org/cgit/linux/kernel/git/next/linux-next.git master
>>
>> [test failed on linux-next/master c79c85875f1af04040fe4492ed94ce37ad729c=
4d]
>>
>> in testcase: kunit
>> version:
>> with following parameters:
>>
>>         group: group-00
>>
>>
>>
>> compiler: gcc-12
>> test machine: 36 threads 1 sockets Intel(R) Core(TM) i9-10980XE CPU @ 3.=
00GHz (Cascade Lake) with 128G memory
>>
>> (please refer to attached dmesg/kmsg for entire log/backtrace)
>>
>>
>>
>> If you fix the issue in a separate patch/commit (i.e. not just a new ver=
sion of
>> the same patch/commit), kindly add following tags
>> | Reported-by: kernel test robot <oliver.sang@intel.com>
>> | Closes: https://lore.kernel.org/oe-lkp/202408251741.4ce3b34e-oliver.sa=
ng@intel.com
>>
>>
>> The kernel config and materials to reproduce are available at:
>> https://download.01.org/0day-ci/archive/20240825/202408251741.4ce3b34e-o=
liver.sang@intel.com
>=20
> Oh, this is a weird one...

As I replied I think lkp simply reacts to the BUG: in dmesg and doesn't
filter it out as an expected test output.

> Do you happen to have either the vmlinux ELF file that this issue
> happened with, or a version of the bug report that's been run through
> scripts/decode_stacktrace.sh, so that we can tell whether the reported
> slab-use-after-free is on line 1029 (which would mean that either ASAN
> is not tracking the state of the object correctly or the object is

The reported freed stack suggests the object was already freed by rcu, so w=
e
should be past the rcu_read_unlock();

> freed earlier than it should) or line 1039 (which would mean the
> KUNIT_EXPECT_KASAN_FAIL() is not working at it should)?

There's also "ok 38 kmem_cache_rcu_uaf" in the log so the kunit test macro
is satisfied.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/4fbe9507-13b9-4af5-88c3-63379835f386%40suse.cz.
