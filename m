Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBTVCR6PQMGQEIA34BOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 1C1BE68F39D
	for <lists+kasan-dev@lfdr.de>; Wed,  8 Feb 2023 17:43:59 +0100 (CET)
Received: by mail-lj1-x240.google.com with SMTP id l1-20020a2e9081000000b0028b97d2c493sf4824037ljg.2
        for <lists+kasan-dev@lfdr.de>; Wed, 08 Feb 2023 08:43:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675874638; cv=pass;
        d=google.com; s=arc-20160816;
        b=JImYOYEKhQ6TkB5SVS54ghtUgM9dDtimrIgHlNkXkGtiB4FMkjk0hFfE2EADBBzAUf
         FSU2ID3c6pMeHAMFzNZWS1o5Fqag8zT1E9QIC6bBsbP9ZDdEW1qmkIXQnI7SMHwnu8Qk
         oudAgoQStUzzfnGzn61M9rd8E+GN928wCozqS5/LgjFEhIrkbHRy7ZKgdqEXcz90M4PH
         uLaTHSVlWHnhMJmAKnHHrAtffhpTx5qhtrYjwcc/xhYbobvQ89aE5BpYhos3s7PopKgE
         bCQoKlSjzp45PGoQj4mcEP2p/iz7lCwsIdULHT01pjB2TBE1cRFHM2Y1Anow9IDYjM4x
         81uA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=aLJYcLjGrp52DIl4OJS73slHGczrb5sSu58dS/hHhdc=;
        b=t8/F7VJ0z3oRGXHWIqBRpWEMfSVTh1Zs1bfsYD0M4Td6J5zdqhZbHv/5cAiwa3e3XY
         MVj+1TrJE5Hsweg0WXZiB3pg1ekDKuGFWP95aSqMDEmZxThNJLD8/eMdolP5TBfxkvcF
         TvTOsSB9Yc+wzpfxbVagdrDfBpAsEKArJq5DhsgdAFLiFfpdtkEBPtbDM9XJ1CyM58LB
         URJKNkM4o1MkzvsfyVDHzu2eYc6lne9qIDoxefC7vxV3x1pRYJWoMU0sM6fPnr8hXpZj
         x5ztaxr/6gC4+s187VKW5TLHAkD0Oviberp7SE8mZNEvT8g6kJZap5gkmYqOg8SNCYr9
         7b5g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=KnJu5ARZ;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=aLJYcLjGrp52DIl4OJS73slHGczrb5sSu58dS/hHhdc=;
        b=fumN0/U4G7PHzD4e4AdKlz/PzYBrmZfpH+eZTb89OyfBDjcToa9rI4RM1CEUB4+Zkr
         XNrs2Bxyt/H2tgdhUCljsicsejzovgg5e/EPeQyNewRgvHdFJIUnEbkTCG/qtCxpL5KQ
         pDTWWrhuDS4MREaZ1SO8AKM6eCMsqJiW7nffmA4g9hgjdkp7MuQpZVoVtfcYFLCwSHL3
         p2aZr05SnrZNSIfy96yysAMtNv54DvSIr3l6pa0BMQjV5t3WK2XNLHpPMoEYdpDR0xNe
         IdCeygTg6RuWFOVoAZwY9ANwTq91vJWvp6PFsVvGvDyJGi1E4azWeGHXn9BEBVVN8Qd6
         w8qQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=aLJYcLjGrp52DIl4OJS73slHGczrb5sSu58dS/hHhdc=;
        b=YbaquRgwrbMhktOAbpMaZ72Un2D7w497eCnd/l2LXbpaV5LWEigvfBy2X5wsoRylW4
         FSdEUc19WY1BL+b4uhD8M684aribGH+Yrh1jBN15E+MpZiXhbjUhF33ceTVRCBwfig8x
         nyUKlRCJEQbZ583mySWfS17GvTzVGqrrRk45RYKoE8mgDH+dMU7RUk64LatzqyyCOF7h
         K9xevZCahnrOipAgDIeHM3rGkJj3GjaG/zl0SCS6efNmmQcKXhgpGlsUqAHmEXVXiESR
         P+Ddb3+7qKeRKuKXspi+gDKs4Gh1fXVcnn4+w6j/D9/84xmt4OwN2aCMnCk02UMBbXUj
         K7Kg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKWr7FBKPQ7RGJcFG4f9kt1wiuqXE9o+xTmU2oEnXi/tV+ZUuX8C
	S+eHA7Xz2ZobUFyzoFeh4+I=
X-Google-Smtp-Source: AK7set/mxBCa86ixz2jIr8PAeCv+LtwHnQ3lVRwMTty/XWnlggqm2SzYDnx7K4E8L1E1aqKrhzMCWQ==
X-Received: by 2002:ac2:46dc:0:b0:4b5:9055:141 with SMTP id p28-20020ac246dc000000b004b590550141mr932148lfo.200.1675874638403;
        Wed, 08 Feb 2023 08:43:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9348:0:b0:27f:b767:aaf6 with SMTP id m8-20020a2e9348000000b0027fb767aaf6ls2907291ljh.3.-pod-prod-gmail;
 Wed, 08 Feb 2023 08:43:56 -0800 (PST)
X-Received: by 2002:a2e:be0a:0:b0:290:6ac2:34 with SMTP id z10-20020a2ebe0a000000b002906ac20034mr3094289ljq.29.1675874636643;
        Wed, 08 Feb 2023 08:43:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675874636; cv=none;
        d=google.com; s=arc-20160816;
        b=b9Tl+qdrIRGbvBLzUSDNO+8SyKAOo5liMnx8iQOVDZoRQFDR9IjfgTP8pq4otOYLyZ
         +HQ//3YeeBTknn78p0IU/gQhlZgcKiE4tqrwF5IF5Uhepj4J4VYszLwG5dyY7dqt66m2
         q9SGe88XNuWfZ553h3Jnu+3P00ZWACqeOSonyaq5Iv46urCGBvn10F2WyB5NK7CZVbf1
         NnqSRibPqOMTxTp45lwpSpf0UhsiquMkwovsUBTolLy+ooWbGOcJFFn6RvLDf+sJvLlh
         xWPDu2GMN/pfUHqAX/cKDSYn7rgF1O5kXDguIMTYZIYzP5aOlBXmwHHW6+qBgJzMN4hZ
         vlrQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=O8k3Rjg4PaCS2IxrnyzGhVgW/FDjVB2k5vyLOUXYNc4=;
        b=CAHCLuPXFtAoVbIwgqZ4fMZfyDfyB3d+65DYrhCRetWeSS+ivm3iUHFaP0uz+WQgOZ
         Qs5vNg5r1nUp1f7ZJdPffqnV2yMjb978P3pWWiUFCVW6+5SMAompM/6JJLJ9wjKbaiIq
         n0FmUc69UyhYdN1F6FrRO1N4kcr/6UQqz8R+8qycQYZ8/kXcE9ejul1wDZINhzPGmcB/
         ASKNFlqUB1qwG1N+2yt/A0/op3u8PTrUOg5eSJgF3UAIJNVUSdMIqOqfDQoTkDZ0MOqy
         6/7OSXEvWAAYCby50a+18RGNrnwhqmDYD9aSWpLXmEbRTUYrO50RJpKKSrRpG1N0uYUX
         uafQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=KnJu5ARZ;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2001:67c:2178:6::1c])
        by gmr-mx.google.com with ESMTPS id a16-20020a2ebe90000000b0028b731e8e20si834820ljr.1.2023.02.08.08.43.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 08 Feb 2023 08:43:56 -0800 (PST)
Received-SPF: softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1c as permitted sender) client-ip=2001:67c:2178:6::1c;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 14C65341C8;
	Wed,  8 Feb 2023 16:43:56 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id E4BF31358A;
	Wed,  8 Feb 2023 16:43:55 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id TBQfN0vR42PsYAAAMHmgww
	(envelope-from <vbabka@suse.cz>); Wed, 08 Feb 2023 16:43:55 +0000
Message-ID: <00da0073-745c-ddef-5e9d-960346adef73@suse.cz>
Date: Wed, 8 Feb 2023 17:43:55 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.7.1
Subject: Re: [PATCH 11/18] lib/stackdepot: rename slab variables
Content-Language: en-US
To: Marco Elver <elver@google.com>, Andrey Konovalov <andreyknvl@gmail.com>
Cc: Alexander Potapenko <glider@google.com>, andrey.konovalov@linux.dev,
 kasan-dev@googlegroups.com, Evgenii Stepanov <eugenis@google.com>,
 Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
References: <cover.1675111415.git.andreyknvl@google.com>
 <fc73ab8b1469d476363a918cbdfe28e1388c043a.1675111415.git.andreyknvl@google.com>
 <CAG_fn=WxZf_kfn8-G8hvoxvUT8-NKNkXuP5Tg2bZp=zzMXOByw@mail.gmail.com>
 <CA+fCnZdOFOUF6FEPkg2aU46rKYz8L9UAos4sRhcvfXKi26_MUw@mail.gmail.com>
 <CANpmjNNgoHdmZEmnOMzBTXZ_Px=fipg-iSk3Hv1fE7MO7+fovg@mail.gmail.com>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <CANpmjNNgoHdmZEmnOMzBTXZ_Px=fipg-iSk3Hv1fE7MO7+fovg@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=KnJu5ARZ;       dkim=neutral
 (no key) header.i=@suse.cz;       spf=softfail (google.com: domain of
 transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1c as
 permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 2/1/23 13:38, Marco Elver wrote:
> On Tue, 31 Jan 2023 at 20:06, Andrey Konovalov <andreyknvl@gmail.com> wrote:
>>
>> On Tue, Jan 31, 2023 at 12:59 PM Alexander Potapenko <glider@google.com> wrote:
>> >
>> > On Mon, Jan 30, 2023 at 9:50 PM <andrey.konovalov@linux.dev> wrote:
>> > >
>> > > From: Andrey Konovalov <andreyknvl@google.com>
>> > >
>> > > Give better names to slab-related global variables: change "depot_"
>> > > prefix to "slab_" to point out that these variables are related to
>> > > stack depot slabs.
>> >
>> > I started asking myself if the word "slab" is applicable here at all.
>> > The concept of preallocating big chunks of memory to amortize the
>> > costs belongs to the original slab allocator, but "slab" has a special
>> > meaning in Linux, and we might be confusing people by using it in a
>> > different sense.
>> > What do you think?
>>
>> Yes, I agree that using this word is a bit confusing.
>>
>> Not sure what be a good alternative though. "Region", "block",
>> "collection", and "chunk" come to mind, but they don't reflect the
>> purpose/usage of these allocations as good as "slab". Although it's
>> possible that my perception as affected by overly frequently looking
>> at the slab allocator internals :)
>>
>> Do you have a suggestion of a better word?
> 
> I'd vote for "pool" and "chunk(s)" (within that pool).

+1, also wasn't happy that "slab" is being used out of the usual context here :)

Thanks

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/00da0073-745c-ddef-5e9d-960346adef73%40suse.cz.
