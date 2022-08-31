Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBU4SX2MAMGQE5SFGLXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 5D3225A82D8
	for <lists+kasan-dev@lfdr.de>; Wed, 31 Aug 2022 18:16:20 +0200 (CEST)
Received: by mail-wr1-x440.google.com with SMTP id j22-20020adfb316000000b00226cf7eddeesf2429293wrd.23
        for <lists+kasan-dev@lfdr.de>; Wed, 31 Aug 2022 09:16:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661962580; cv=pass;
        d=google.com; s=arc-20160816;
        b=eLETu8/d8GW4/nONiKjHaHUlC+z+eltiXgS1/sR9zWkX2gbWvtshE13J0kd+6mRZ0i
         MMs3zpLjsRRbHBvTUn6NKeJOClJJ92bcTgxJA917u14MsP3ypSHBpT+rbAqEPtwPn5tt
         LFcje8Zq1MqFI0Zu74hqMU+89ZoeUQGmHBV2mu3rQPbYQoutZVwGs5oy/uY4+rKWt3/Y
         IQlcj0Sub+RnPw0kixq8hmIlhDF2N2VuNNTS3iT9+cpvJhtpAvQ/xL17OhGg4SP9kwHU
         NYZv35amPav2z+uBmQdNDlCpu8ZuyTS3sL440gapGmolOjIYgwAdmVy/VS5h9k78vSyq
         WlfQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=QLoub1k9dOJDU1c+DjFog5Kk1QmAYhJghQVUlN+OFLM=;
        b=qWGdca8tlE2ZXCG+5jcfmO9r56kaqMoU3fObA+ImcJ6ojyVi1KOnSf78iEFSjAWgAh
         4JDbuSdoPumxQLN3bRHb1zi6R/WvZ1PBlHvEH2XLmdve1otVBIRkBQ6r6SKh5UqU54ji
         UaAp68VWqyQFfcEAb/VQCaP7pMmXLIcsQjgTs+ks9mERn8zrjo3v+yWymQGuzJOJMtsj
         gL5BVuaiZorR77Mxnk3hzoSoK7WO3IuC4mV00ST42V+kceyUQQQUi4OOEeUgml+UyTt4
         LOml53VRRwEvRaNSg5bZUEUdFkAkxiPVqC29RZb5foWAv5J2NiAM1Zh1seO9ksYKzX8R
         uBTQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=zBDQYaA+;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=SuTDp3Ij;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc;
        bh=QLoub1k9dOJDU1c+DjFog5Kk1QmAYhJghQVUlN+OFLM=;
        b=tedpKisca2UrsG60v8jCyLmF/iqwTR6P55vIG/6jsmrIXesjdLXD6X8A8qD1MfAn5I
         uK1jBr9R1f6f2IWMk7ZsjeCN733d6uPuqBg4Z45TnyalZAI1EgkJ/AQ+uc9ax/6LxLaR
         TDU799RTa5+IMcU4Qn7klWuZTzPHCYTWLm4I0TjDjIQ6/9r4rhgBd2fjLACOsH3YMxsZ
         6RCaSdXCvYmEfpHPKQYYVEn0kRHzCAbBpGyMkDSbS0iEqzxBB6reeciLP7hUNdp17EFT
         qMCKYqW2CeMAlRIC5dL8ApHDgeYx6hmC4E7sMtJvgVTVTX8UaMbgldYdsg/qFrOP/Za5
         PdhQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc;
        bh=QLoub1k9dOJDU1c+DjFog5Kk1QmAYhJghQVUlN+OFLM=;
        b=TJ7jX2Qa9iYv2MakpNT+wALH/zzedrJ5BcUzDr2pDUnUOVlKDpnqkPxr+I8oAE7ALH
         aSaVKWwgszb9DQzameOVb4XEguKNhZVTpc7FLnjAJ3cYj34QBTNI+9f5/QE0V3LRMmyE
         qX3/vtyRF9J7LhqYetS0jXuG/PeY0WyBsRvQUkYBe9btjQ7sZoMxmkbvrzlix/afwxK8
         5BTLq8xOqHGlfJr5Kdo/IftPMR44OFAKwi8evezf5vKZjyQY+Rp7WB478T7MD7X4z5iK
         ITuhKRQJTTjOewvEpVW4Izn5195Pb/f3R5QsMvkfKLppvGKzr+xCD17kUDBrbe8MKR0Y
         1PEA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo1OItREQq2ougIyk+sIiUuwGE4c7qfEOV2gIkvopxaqplkc0xoa
	+u7E0LU1WV+OW7qFo480BCI=
X-Google-Smtp-Source: AA6agR4x/fb/yyHuEaAvUedvBDoUL8MEDCd0J04uKTIf3SENbT/5bUa+7groQwxGW9hwSubVR3eThQ==
X-Received: by 2002:a1c:4b01:0:b0:3a5:94e8:948e with SMTP id y1-20020a1c4b01000000b003a594e8948emr2486970wma.197.1661962579866;
        Wed, 31 Aug 2022 09:16:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:f30b:0:b0:3a5:4532:b3a6 with SMTP id q11-20020a1cf30b000000b003a54532b3a6ls834248wmq.3.-pod-control-gmail;
 Wed, 31 Aug 2022 09:16:18 -0700 (PDT)
X-Received: by 2002:a7b:c5d3:0:b0:3a8:3d5f:4562 with SMTP id n19-20020a7bc5d3000000b003a83d5f4562mr2535062wmk.78.1661962578632;
        Wed, 31 Aug 2022 09:16:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661962578; cv=none;
        d=google.com; s=arc-20160816;
        b=uSocGEfFjx37DqgUrASrfSsi0hOn2yQBuxyYa1S3uTAA0mAtkxdpYyrasto3UTJ5Ni
         eA2q3f5v73VCqMa/F0JpEobK1W9D4qyWpIdFwvKJHiyK9/L4Kla2jR+o29UgZcCG70BX
         I7+WzG/3XptzGBC/Ckhn3OXqou+inKXQ7v4gYsV7YiNBZCB6CXmFF5VUIkfptWEz+ziu
         K/D3zMKSPwYk8nX1y8Y3DeZDvhp7gFT1/f0WHQOpnq+cQ9ME/x3fuRuAjKiKMls520K5
         Oa3j1bAbIuxnAjYi9BN2GDDWc/C9QvKn47mnPcvH8XtSt2PV1HcaYSvHleeRJRYgmjVX
         lJnQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=o6HPf2L5K/Lf19WA17JOPqDvb/Xtjl8d0vphRCxEgqI=;
        b=abQgAzGzDVEgaeEQzjb++1NTy9WIsXUTTnoCE6yZhHTuTHcYJrhLYozIJvhBW7NTrJ
         vuNJooCtVJZMGXm2y8DWFzkLKmNApl9pqJ3Z1Dsb1LwhGx5BsPDFoIx833gefpQkVZ7S
         4vyT+ZW0ZHMMev/dC4YfwGmWuqpLG3zMjrPVR2XjLL2EfgkA9Z0o4pnqRF9gRZflESKh
         r/9VwIT0UVZfXjBuztNWGJg1F+HGDYiAwc266MDNBlflX+F+L0t02Mh23kwO2jQI4wMB
         tFdAuG9beWgtIN3Fl4WVPKb6yu1ZpF+baAlpnZw4/+eglmXhh76d6weWu1YbJUwH1AI+
         wqtg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=zBDQYaA+;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=SuTDp3Ij;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.220.29])
        by gmr-mx.google.com with ESMTPS id bx5-20020a5d5b05000000b00226e3ba2090si278464wrb.1.2022.08.31.09.16.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 31 Aug 2022 09:16:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) client-ip=195.135.220.29;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 4836A1F8B5;
	Wed, 31 Aug 2022 16:16:18 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 191041332D;
	Wed, 31 Aug 2022 16:16:18 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id J35VBVKJD2O8AQAAMHmgww
	(envelope-from <vbabka@suse.cz>); Wed, 31 Aug 2022 16:16:18 +0000
Message-ID: <7edc9d38-da50-21c8-ea79-f003f386c29b@suse.cz>
Date: Wed, 31 Aug 2022 18:16:17 +0200
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.2.0
Subject: Re: [PATCH -next] mm: kence: add __kmem_cache_free to function skip
 list
To: Marco Elver <elver@google.com>, Hyeonggon Yoo <42.hyeyoo@gmail.com>
Cc: Feng Tang <feng.tang@intel.com>, Andrew Morton
 <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
 linux-mm@kvack.org
References: <20220831073051.3032-1-feng.tang@intel.com>
 <Yw9qeSyrdhnLOA8s@hyeyoo>
 <CANpmjNMFOmtu3B5NCgrbrbkXk=FVfxSKGOEQvBhELSXRSv_1uQ@mail.gmail.com>
Content-Language: en-US
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <CANpmjNMFOmtu3B5NCgrbrbkXk=FVfxSKGOEQvBhELSXRSv_1uQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=zBDQYaA+;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=SuTDp3Ij;
       spf=pass (google.com: domain of vbabka@suse.cz designates
 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 8/31/22 16:21, Marco Elver wrote:
> On Wed, 31 Aug 2022 at 16:04, Hyeonggon Yoo <42.hyeyoo@gmail.com> wrote:
> 
>> Maybe you can include those functions too?
>>
>> - __kmem_cache_alloc_node
>> - kmalloc_[node_]trace, kmalloc_large[_node]
> 
> This is only required if they are allocator "root" functions when
> entering allocator code (or may be tail called by a allocator "root"
> function). Because get_stack_skipnr() looks for one of the listed
> function prefixes in the whole stack trace.
> 
> The reason __kmem_cache_free() is now required is because it is tail
> called by kfree() which disappears from the stack trace if the
> compiler does tail-call-optimization.

I checked and I have this jmp tail call, yet all test pass here.
But I assume the right commit to amend is
05a1c2e50809 ("mm/sl[au]b: generalize kmalloc subsystem")

Could you Feng maybe verify that that commit is the first that fails the
tests, and parent commit of that is OK? Thanks.


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/7edc9d38-da50-21c8-ea79-f003f386c29b%40suse.cz.
