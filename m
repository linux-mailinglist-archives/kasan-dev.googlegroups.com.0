Return-Path: <kasan-dev+bncBDXYDPH3S4OBBBVJZ6VAMGQEUQC5FEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 5456E7EB782
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Nov 2023 21:11:52 +0100 (CET)
Received: by mail-lj1-x23f.google.com with SMTP id 38308e7fff4ca-2c59e2c661esf838321fa.1
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Nov 2023 12:11:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699992711; cv=pass;
        d=google.com; s=arc-20160816;
        b=fdNwCl72c4eQcI3IqVwm65KnRgEkuVeZm8ShXTHbtCNq8atgujn4F277DUpxP1hWRY
         NuDOY3fqXNk76DQcP8MPYmFk3pHFydB3XbDjbGHGJU4NbYf8rdBVY1xOU6zQ44MwiT/C
         PbfMDk1oTYfGNO97jLZd6940BLuchPNX/4DFdm9QrFm3v4GvAqrNbQbUcHL35JOFWO4s
         v3kU9W8UjD23tY18+2VadYpFty6Dd32CjUzIujUC/hYk6Qus6d14nR2in4Dkmw1f3/Kt
         OIb5pCZ8sJC5Ky1YmKxhLDtHO1tmDOlNmzh0pkSKsMWvixs2YsCpo/FGAKOWgr3BXXos
         PKXA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=noWDUhxHmqGmzxqggm+0pOK1ShGyItWLLBIZUwfs8dA=;
        fh=ZYn9MgmVpwKFi+h1WPMvL6yHYpyqaynezClwMkX7/CM=;
        b=xCL8b9XFdykbHUWWP32GxvVaqsjaep0DLTW6/n5IBKWZW68X5nt6tufkEBjeVkeIIe
         sQKLGyL/tZ4sKDkJdL/9r3TnX2RBcCirbQoGTyHN1kOAjLq/HlWMwboyDA9O4Uf8DfY2
         teEpGFepHz4uurt0lh/udEmxFz0C1xLlz0GHRVi4uwgQVu6XTbegJpxnhYks938yMHfr
         Ff/T2l///9KGlsrhHtHpA2SLswa9IzImgp0X358J4UQPdBaGvWxnLTe0PKP3YLjw/nb2
         3Q4IEJ6I4SWfHG0uDCVBRkUxRVn9IuOHtLcDZm75EK74ybFUcPjC8J7iSllR7hFuCYm5
         e+CQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=QztLg3ps;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=NcSJZK89;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699992711; x=1700597511; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=noWDUhxHmqGmzxqggm+0pOK1ShGyItWLLBIZUwfs8dA=;
        b=HRS3Jf5uUsqPE82e4PClzAXCY3xIcksixoQI9KJEYDXnQEU9ZmrVM13pqoTBLDoPbv
         GsZoffYNiAvDc/pPiqmyM5epb/VbILaU61oiujcR5N8TxqaDnJqcOExU9oJa7JbOsUfL
         j/Xru3IJXI4lHq0oqDLQe2tauoL3uWjJSGAohWm7dK92MO3j55mxuYTwzhoQ3vzVnHbu
         uRLSIK9fv4DUv3KpcQrX52U4pZV1WccW2slVaHeF8QhHX9/PVV+7Zk4eKizktSbDyOZr
         RVaFAJHZ+s/K/7eRe5dwI8BeIfKuvPpvhk7a0fm7EgPbT/uqYzTSI1gJ+eyo7IYmkWvt
         MwaQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699992711; x=1700597511;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=noWDUhxHmqGmzxqggm+0pOK1ShGyItWLLBIZUwfs8dA=;
        b=aY0J57p3zxLf0RkcfD1r0Dgqa5SxcD0sQc/J8U6b47HUypWYzywMiwHPrsek05hU4v
         Y/6PwpaqhtjF3WWPWr3hvTPA0dmLupvL/rPIjEPKOizh8xQKzHnNglb4qJPnX2t4+BB3
         DPRNHsyuVESAhUBobjTkmncFo4UOoC8CP4Q0RqdVUdq+K7Q9mvWtxKv7Ck4MPyYRsAWK
         z9h+BRS8tn4C+4i6LYrG2BSek2eAjn2+M/jqju6BXOhSm6p9bzNQDlNtdkXje9NijRIp
         NhY3oZYKxPKcfbAyzPsoILPMqNlftVQH/PsXwKPKVk4vH5udOUNm4nXQ+jR//B5cbL9f
         C2yw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwUx33LFPEMHUkWwlSP1NlMTNAGeP0v0OxwNcirTBo/pk9eD6ne
	/5xwBtkkUhas4Li+26mIqtI=
X-Google-Smtp-Source: AGHT+IGLbzrCtIjX3RzX7PxsEwHWZekwPztv94gLWHMHvye4d7vxaswwW+cAeWafB44zkZcyvZKQjg==
X-Received: by 2002:a2e:9ec9:0:b0:2c6:ec37:fb5 with SMTP id h9-20020a2e9ec9000000b002c6ec370fb5mr1120249ljk.10.1699992710774;
        Tue, 14 Nov 2023 12:11:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1cd:b0:2c1:261b:7353 with SMTP id
 d13-20020a05651c01cd00b002c1261b7353ls1070411ljn.0.-pod-prod-00-eu; Tue, 14
 Nov 2023 12:11:49 -0800 (PST)
X-Received: by 2002:ac2:4845:0:b0:507:9b69:6028 with SMTP id 5-20020ac24845000000b005079b696028mr1326303lfy.24.1699992708760;
        Tue, 14 Nov 2023 12:11:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699992708; cv=none;
        d=google.com; s=arc-20160816;
        b=t4AW1DfzFn34xu6+FtRMBWJZBK1eRQfGp4lfsqe7hDx0lNV34BEj+HGsv0awuPNHF0
         wGKGYorNq9T0Qq1Tq9rRA4+hd8nyW2xfNZVguBjUiKSzKE4JXdibM6GNH+xFEX4Bq0tA
         q68MdBHS+M2KBs3hP76SdVYgrjru7LyKhQMZwkwdXrHEZnwc8yGl67pq6QetNqkritfQ
         VR57KPb+HyWg0vSNFXTTr0pITFcXw0jkC/bK+nNNOHi7wWcUFI3cth2sDuDSLWnSSOuH
         GWHONHCMilXZ+TRP+vpF1BQhDzn/T8Z9GiUrBI0njYOy1vgCrGbSvWBqvMryikfvDmb4
         qmwA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=Jx5LtWmsLR+LfLuIaijRwnFRntSIu1BC0epYmgHcaMQ=;
        fh=ZYn9MgmVpwKFi+h1WPMvL6yHYpyqaynezClwMkX7/CM=;
        b=KP+FEUykDfCfZfdLwSpSERh29koEFJMtw4VlpyQ/mxvzCtKfyfiT8r5CHTbxw3n289
         7AT0piwZABj+xfVajeSALd6p09wb48EdfBOjzdwHVeQpvsn3YlQmiiUkaon4E/ycghD9
         oK4XXrmwdaIne7inMlHoyDtCNoLCerS7xKcTjnXofN1RDHMuT9gcQPbQNIZJgOsgfASe
         75mJr1LKVEWWORru2UeY78gTdtAGd5O7ugZD9ZO7EdhvoLDeFczFLiFGQ+CvSjoBh/cC
         BJAsBcYB9YvaZ9V/eJw2lSDbnkAyv58QGw3ywCJ0T6GV1JzI6G2n9qtaHPdxx2YpsAFP
         Vsow==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=QztLg3ps;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=NcSJZK89;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.220.29])
        by gmr-mx.google.com with ESMTPS id q12-20020a0565123a8c00b00505701698aasi286784lfu.2.2023.11.14.12.11.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 14 Nov 2023 12:11:48 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) client-ip=195.135.220.29;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 78AB920430;
	Tue, 14 Nov 2023 20:11:47 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 1F4A913460;
	Tue, 14 Nov 2023 20:11:47 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id 8LsfBoPUU2V+WAAAMHmgww
	(envelope-from <vbabka@suse.cz>); Tue, 14 Nov 2023 20:11:47 +0000
Message-ID: <55a589d7-edcc-6db4-759d-c928577cba8b@suse.cz>
Date: Tue, 14 Nov 2023 21:11:46 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.15.1
Subject: Re: [PATCH 01/20] mm/slab: remove CONFIG_SLAB from all Kconfig and
 Makefile
Content-Language: en-US
To: Kees Cook <keescook@chromium.org>
Cc: David Rientjes <rientjes@google.com>, Christoph Lameter <cl@linux.com>,
 Pekka Enberg <penberg@kernel.org>, Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Hyeonggon Yoo <42.hyeyoo@gmail.com>,
 Roman Gushchin <roman.gushchin@linux.dev>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, patches@lists.linux.dev,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>, Marco Elver
 <elver@google.com>, Johannes Weiner <hannes@cmpxchg.org>,
 Michal Hocko <mhocko@kernel.org>, Shakeel Butt <shakeelb@google.com>,
 Muchun Song <muchun.song@linux.dev>, kasan-dev@googlegroups.com,
 cgroups@vger.kernel.org
References: <20231113191340.17482-22-vbabka@suse.cz>
 <20231113191340.17482-23-vbabka@suse.cz> <202311132009.8329C2F5D@keescook>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <202311132009.8329C2F5D@keescook>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Level: 
X-Spam-Score: -2.65
X-Spamd-Result: default: False [-2.65 / 50.00];
	 ARC_NA(0.00)[];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 RCVD_TLS_ALL(0.00)[];
	 FROM_HAS_DN(0.00)[];
	 TO_DN_SOME(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 TO_MATCH_ENVRCPT_ALL(0.00)[];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 NEURAL_HAM_LONG(-3.00)[-1.000];
	 MID_RHS_MATCH_FROM(0.00)[];
	 DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 NEURAL_HAM_SHORT(-1.00)[-1.000];
	 BAYES_HAM(-0.05)[59.88%];
	 RCPT_COUNT_TWELVE(0.00)[23];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 FREEMAIL_CC(0.00)[google.com,linux.com,kernel.org,lge.com,linux-foundation.org,gmail.com,linux.dev,kvack.org,vger.kernel.org,lists.linux.dev,arm.com,cmpxchg.org,googlegroups.com];
	 RCVD_COUNT_TWO(0.00)[2];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=QztLg3ps;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=NcSJZK89;
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

On 11/14/23 05:11, Kees Cook wrote:
> On Mon, Nov 13, 2023 at 08:13:42PM +0100, Vlastimil Babka wrote:
>> Remove CONFIG_SLAB, CONFIG_DEBUG_SLAB, CONFIG_SLAB_DEPRECATED and
>> everything in Kconfig files and mm/Makefile that depends on those. Since
>> SLUB is the only remaining allocator, remove the allocator choice, make
>> CONFIG_SLUB a "def_bool y" for now and remove all explicit dependencies
>> on SLUB as it's now always enabled.
>> 
>> Everything under #ifdef CONFIG_SLAB, and mm/slab.c is now dead code, all
>> code under #ifdef CONFIG_SLUB is now always compiled.
>> 
>> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
>> [...]
>> diff --git a/mm/Kconfig b/mm/Kconfig
>> index 89971a894b60..766aa8f8e553 100644
>> --- a/mm/Kconfig
>> +++ b/mm/Kconfig
>> @@ -228,47 +228,12 @@ config ZSMALLOC_CHAIN_SIZE
>>  
>>  menu "SLAB allocator options"
> 
> Should this be "Slab allocator options" ? (I've always understood
> "slab" to mean the general idea, and "SLAB" to mean the particular
> implementation.

Good point, will change

> Regardless:
> 
> Reviewed-by: Kees Cook <keescook@chromium.org>

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/55a589d7-edcc-6db4-759d-c928577cba8b%40suse.cz.
