Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBTEP7OOQMGQEGWIU2TY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id DAA26665DE5
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Jan 2023 15:29:32 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id m38-20020a05600c3b2600b003d1fc5f1f80sf10803717wms.1
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Jan 2023 06:29:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673447372; cv=pass;
        d=google.com; s=arc-20160816;
        b=FLMVoUDWb1tYBIDlpN0lByxlgOfqDqiBU4tEYMtVEaP9SKLVqa2ONOrDQMGnFvzpzO
         W86KUCvQ3ZsvpOoCg+CB89t3iYpADr8SWMdmPrrL5mhZ1X0+ZbED8J6NzIGxV4PYRWU7
         3nhEJYcn5Knn4PwLYUO12gPU0cla97z7wB/KrVKVrV+XVYVt8r2PlFsjeiYXO0LfBtqw
         3U0iomDgiMpjf9DyBTmHoGRWpUKdr6pVTWHx8vpqkIjcAczGnUV4S6pPlpb/uMfTCWMB
         I9pyyaQGPaaUkdO5NSInV/mPYSEPVZg50a3hqivufeZUs33L3wUmkVaCNGz98tX00NGc
         KOWQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=LTOzhJ5rKrIwMKtq6isMNNdzVW6OvSlfo4oaHdTF6wY=;
        b=W25DOuLUUqkNF2gVmTiBht7PsUiI5F0kUaC9hCNUTz3N0HaES9qS7PMmd9h2CFXcvZ
         UZz6KQAwDq/hj7cGT0U5F27/4Fy/UD44iteU/Q507Y/SULisiX829QDCb4Q7s+geKIyH
         wMh7ZjDKRwdK8mMG4BeL5Kjlc63CDV23hp4xQ5o0vm5czLwDdRuKnOVwHF2+safWQvq6
         X9V7Eh5htfDybtz9TrZ6gehJYH2BU/QYAH0D+/LunGEl1QBu94HgbzDzYsF1IVqh+4s9
         Dp60d2H0NLoZeCoCGcIdqbw+oaGuaXx0MpWSeBeEHmYgHsgrdpNTC8jfJcAmlf8a1h7C
         NF2A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=yTf0Orrq;
       dkim=neutral (no key) header.i=@suse.cz header.b=NMWlc0vL;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=LTOzhJ5rKrIwMKtq6isMNNdzVW6OvSlfo4oaHdTF6wY=;
        b=d64v1R9kXG5i1z97deTvEZ7LhrZzs7sqBzydOG17BAFT2J0ZIJE640RB1PKIKRafUy
         62BHr/GO38Bc9LJrS8NaGqTmSqXABiyc+EjgKY5b6gHim15kUn8UQ7ZVuuEZ4IBUKzT7
         iVGLICQ7H3onzckx+qzvxwilmo4UkI/kBDp72DadNaYdIYNRoI9Dkoozniss4S8azP/T
         j1ZsPBlUtXiKLhqU+z5/IP3sdTFmnTjzX/x2vcVYQAqqz3NGeaMFx0svAW7ObApcCXzC
         RX6ukBYdp4RD3Kij5xEj+N+aUXB1/dUw17uDGKA+f9MYP4S+Sm42wLaU2r6kONljDKn/
         LgQg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=LTOzhJ5rKrIwMKtq6isMNNdzVW6OvSlfo4oaHdTF6wY=;
        b=QsaUSt4Ub5a4vw7znM47f5RSLZCNmMEF4osyGePGPiF3DKJql0S178S9ygNtSFTyu5
         Y06O7keue+1P9emG3FqIKlEa1u7lldyXQVnenjtW9SScInnSnRqj9CebPMEGAfc/xCLN
         YG/A65EeNBn/1A29wMUwj3pfmHcIac4gmO/qz6os/EuCri8Mb3Y7OsS0idYaZ9dSi2Cb
         uWEBgVLV4olubaeK2B5dhtBg/ntggCtiQq5gY/j24ilgOhbHDM4TZ7E5+nKjdpjn9GKG
         BRWDBdYlB6swsC+0vruhvhj/ua9MJoZbosR26XTRwM6yw9/gtr692zjjm0Gj31sLkwXP
         8qGg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kr8KrSWtQqsMFYNCatXjfgor42Zq/9kpcVhBvgPU17RScEfzALY
	VJ85QnEKuuWkfg4/eM8xJOY=
X-Google-Smtp-Source: AMrXdXuDS4UzXth/FPc1uJy3NI/l+pyzjhJtFZP4P7JpuU2g+hfojtcQQw+MWHT0buW1/M6I0U2F/w==
X-Received: by 2002:a05:6000:699:b0:29b:2c5d:23b2 with SMTP id bo25-20020a056000069900b0029b2c5d23b2mr1275704wrb.33.1673447372225;
        Wed, 11 Jan 2023 06:29:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:e909:0:b0:3d9:c8dd:fd3f with SMTP id q9-20020a1ce909000000b003d9c8ddfd3fls756063wmc.0.-pod-control-gmail;
 Wed, 11 Jan 2023 06:29:31 -0800 (PST)
X-Received: by 2002:a7b:ce8e:0:b0:3d7:1b84:e377 with SMTP id q14-20020a7bce8e000000b003d71b84e377mr54617778wmj.27.1673447370937;
        Wed, 11 Jan 2023 06:29:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673447370; cv=none;
        d=google.com; s=arc-20160816;
        b=oe7R22hfV28LZ5unh2T5dg/TeHU0zNSFtnf1GCdjkNZaO9O9wAYS6NAxR1JMqRgzN5
         4C2j14idLdE1BFsJM4cSb1n++PTw6Tye1WOOYTOrUuh0c7rIUxkx2ltfH0cy5INMsDZr
         2wvi1CI2DYaYH+rbmTpSDLdUSy5aitHAHJCQtMzLId9QN4nuo5AGw0we5m/bvB0J+TZE
         Ah4T7PSqdRz3lt+kSzizlPn4ik+THuDWvRx0OhIryygNG/oqIx/s8pKUTwgKi0I1GFm2
         YKJv0bhUhh3KmxHb6ip0y+rGaxZjEgEWaN28iKdT2MMt79zaDJkhM0P8mQPoj5BVFimE
         /yuA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=11TdC+X9GAIhdtANdYb0FG8UhriEm5EsKvnTy5Yrh1Q=;
        b=szygbcftSfMgDqO2s6Ja3OqLpjMOGnKki2qcLjAC3J+OjdzGwydMHr4ZqIZUBc6erq
         MaDdA2uL/dXGkAKO8Wx4ruqXI/pIFUCKpdjg/IpjTr+Blh8ZZWm0tKpY5KeMggKf7iix
         QmIXRZTrLo99tef8PBSauuSDzUzBwtbriRRxfTMps2zME79PJGcASbfcgUJOzCbH+Ahe
         yGS54IGOIxiW6uDA/qe6mLIvGpFIg9jMTN2ofI7StdJYyUfDpnnpsO3ZNEiHQMs47K+v
         P94j+82Ig3PYZcnfOBrxXN698lMChgFI1p74B8IvhnV2ia65gP/FPNzg1RnpmYUByTLW
         mFug==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=yTf0Orrq;
       dkim=neutral (no key) header.i=@suse.cz header.b=NMWlc0vL;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.220.29])
        by gmr-mx.google.com with ESMTPS id z24-20020a1cf418000000b003c4ecff4e2bsi750133wma.1.2023.01.11.06.29.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 11 Jan 2023 06:29:30 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) client-ip=195.135.220.29;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 640CE4A8A;
	Wed, 11 Jan 2023 14:29:30 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 3C65D13591;
	Wed, 11 Jan 2023 14:29:30 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id 2NEpDsrHvmPhEQAAMHmgww
	(envelope-from <vbabka@suse.cz>); Wed, 11 Jan 2023 14:29:30 +0000
Message-ID: <953dda90-5a73-01f0-e5b7-2607e67dec13@suse.cz>
Date: Wed, 11 Jan 2023 15:29:29 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.6.1
Subject: Re: mm/kmsan/instrumentation.c:41:26: warning: no previous prototype
 for function '__msan_metadata_ptr_for_load_n'
Content-Language: en-US
To: Alexander Potapenko <glider@google.com>
Cc: kernel test robot <lkp@intel.com>, llvm@lists.linux.dev,
 oe-kbuild-all@lists.linux.dev, linux-kernel@vger.kernel.org,
 Christoph Lameter <cl@linux-foundation.org>, Marco Elver <elver@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>
References: <202301020356.dFruA4I5-lkp@intel.com>
 <aa722a69-8493-b449-c80c-a7cc1cf8a1b6@suse.cz>
 <CAG_fn=XmHKvpev4Gxv=SFOf2Kz0AwiuudXPqPjVJJo2gN=yOcg@mail.gmail.com>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <CAG_fn=XmHKvpev4Gxv=SFOf2Kz0AwiuudXPqPjVJJo2gN=yOcg@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=yTf0Orrq;       dkim=neutral
 (no key) header.i=@suse.cz header.b=NMWlc0vL;       spf=pass (google.com:
 domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 1/11/23 13:10, Alexander Potapenko wrote:
> On Mon, Jan 2, 2023 at 11:01 AM Vlastimil Babka <vbabka@suse.cz> wrote:
>>
>> +CC kmsan folks.
>>
>> I think it's another side-effect where CONFIG_SLUB_TINY excludes KASAN which
>> in turn allows KMSAN to be enabled and uncover a pre-existing issue.
> 
>  Thanks for bringing this up, I'll fix this as Marco proposes.
> 
> Would it also make sense to exclude KMSAN with CONFIG_SLUB_TINY?

If the root causes are fixed, then it's not necessary? AFAIK SLUB_TINY only
indirectly caused KMSAN to be newly enabled in some configs, but there's no
fundamental incompatibility that I know of.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/953dda90-5a73-01f0-e5b7-2607e67dec13%40suse.cz.
