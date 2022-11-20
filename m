Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBUVV5GNQMGQEBR332WI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id B5CF9631542
	for <lists+kasan-dev@lfdr.de>; Sun, 20 Nov 2022 17:50:27 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id q12-20020a1ce90c000000b003d00f3fe1e7sf1210528wmc.4
        for <lists+kasan-dev@lfdr.de>; Sun, 20 Nov 2022 08:50:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1668963027; cv=pass;
        d=google.com; s=arc-20160816;
        b=wfWTT4YeOpb7Dv5pHTqMWJG8Yi+8baW0ROX1uQKCNnVsTjbhemt7CZmC+s39wLWw/6
         k1nIjKb5mDA7550SCtfngv08LqU/eIsv35D9nibm51wqk0P5BpCcacrl1fyEQTAY5NCC
         KkR/TcLbRYtMOjnjRcW/SUZrXVEMqE1HW+dWBhlGLX1KJIQoxYkZGpNCIu2y+oH+eoIq
         zW4QsKJGCCAqOKPFxVPHa08STJFhwsXAzs/2W6yu9hvZ80zIyAax6PPZOHX05+QYveVp
         pbBa0WJXQJ2LAyhap/RcDTlVaUE8cLirRv/x/NuE6GKqk4W8qvjxcva4vJHeaWxk5TFG
         OPUQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=ZtkOR8zVQYOWseHbtFuIUpsDEOCvGLXa8+i3kwl98js=;
        b=Wu9KZ7R2GurwPXyZou913+INdYcgA2gGOumPNX3Zh80HoHWXXG7KxVCxdw9M2zXrXk
         lFfr6NiatWrYpH1od9jUAHzEVTmmmX14YU8FTo8RxHJC74O7lWb6aL4wxAVOkt2hXFwc
         jWg5yHdqrtx8CpTQC9yUigKn8Da2OFQnq0d0bS9Txzd104pstkwlGRcslKQs8jSHZiJ6
         UyiyqIpa7+IUn5GijbVa4AIrqrqKi6j2eZGgM/eFUN6aOuUJCI0fv3e3ZPpad4nJU6gH
         KDWD6OuVnNyKtmEEyCPQKGgtYCo7Ac06hN6KF+U2sMnuyArMsDFLRlWoWSzujODJ82KM
         E30g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=ClCAE1gT;
       dkim=neutral (no key) header.i=@suse.cz header.b=4bUXNii3;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ZtkOR8zVQYOWseHbtFuIUpsDEOCvGLXa8+i3kwl98js=;
        b=QByDryVAgMT8AziNJXy1n3Uitv1BFKw+zw3DLis8IWak758/mKCLYbPq4qS/utKg+O
         WENmtLjZ0YOWIETDJJq3lo+wJuti4jb4QTypgtrgAoyr8j0aL0tmCrHEuA72lIu1ludW
         um9XQx5lGChwVRQLBDYGEbWou2uvByinag+JqotpDUWKHJIxA6JRsHt3QFbobN5MbZ8b
         iVDrrF48TXASWGWJ5Bm810bqu7epP38EJZCQGd2PSNX2InCGvR0o+BkSH0UPiZsGtnAV
         oOfQ6ABLwlWBcKyadCXUuquLS04lsPQyVrDpjMBFDNOI8Ejf6oEuZOZE/DA2luEwmhQW
         A8sg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ZtkOR8zVQYOWseHbtFuIUpsDEOCvGLXa8+i3kwl98js=;
        b=uJ0K9vqoLVTNP1cMxhwmzjuBmtVXEX2dXd2nQRAQSGPTuuZNCz5QsKyyVT9rV9e8+9
         PF13+kgQOEFd11lUWA/acelov3uI9KDX+f3ortLTcEE6CTA+yyNZ7zlBIQ0mn0IpzY0W
         gYpd2w+LaYN525L1ZnnV7r2vCwzDW4XniVkUizd3Mm+PQ0l6FRz97mp7YnIb1yAc1Thw
         NeoSuKiEAagtxreFW6zWOQO7T+TMzgRS5Sp6QY6mdpuoC9FCmnIn2XJA+6eT5K96Eehh
         /bNH4Ey1McbxyNQCzve3/WXUNTCdv8oeipS7dtlkywgFJMUzIAZgromMpoSzdJcGXXvN
         ElZA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pniohQQNSSintFlYDe3NcjmkilxYTwVdSa+qGrc7/l1c0/sSWt5
	h/aSp67XhToB/Qb2yS+bCyI=
X-Google-Smtp-Source: AA0mqf4TZWg4W43MYFlhss2hBTTW7sXOGvKpKE9eHBl1d6xjQ3B8Y7iELii29LwR9UaPziYNcDvlZw==
X-Received: by 2002:a1c:f617:0:b0:3cf:5584:7730 with SMTP id w23-20020a1cf617000000b003cf55847730mr13984823wmc.187.1668963026742;
        Sun, 20 Nov 2022 08:50:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:5247:0:b0:236:8fa4:71d1 with SMTP id k7-20020a5d5247000000b002368fa471d1ls12179765wrc.1.-pod-prod-gmail;
 Sun, 20 Nov 2022 08:50:25 -0800 (PST)
X-Received: by 2002:adf:cd91:0:b0:230:1a1:ac8 with SMTP id q17-20020adfcd91000000b0023001a10ac8mr9187923wrj.530.1668963025217;
        Sun, 20 Nov 2022 08:50:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1668963025; cv=none;
        d=google.com; s=arc-20160816;
        b=R8DDS8uNKUCfX3pG3ByqatKDWwMVqGYrsKqTEqFvn0SboYnmGcPjhQV7XmuKBZL/Ut
         UTcpylBhvOqLrsXmQjjQrud1+d+hKAbZYZCu9OaWUROIKDMF+bHcaj+SX+PItnGo+l13
         H09FbyZ13zBHA7JNdxaggcUqv4vGj1XsAv63a0UrQ/JxlqIARGP8hRbkmgqQGtpQfXU9
         up8mJJcwUsjagBm1J9t5990owUCznB9qG4XsOo9ox0bUT7DMUs3cLMIXvkz081XAANNC
         lNxjbo12xKGMDNgDjAIiIXFb9wY0tJmDM+8lTPo/ktQXUl3Th4PSbkojXEVjgtCFxmHx
         8i3A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=KfVu7FWkHQ2Bojm6W10rAhMWKqZU3HIBARL9zZ8Ec6Q=;
        b=J3YveJzG+dqPilxEhZE8Xqrs7Win7qDhhy99iCjXM6W0AwVc1lN1Ku6BX/ZyAD+kpB
         r4UzNiLlZ0TMKT5QpAGctvi014D4GX5cHVtS8EYh+JLtlx3R6S50LQL9/WZSFjW4uL1S
         zntIGy7KUnAfAMpSkpziAFTOvYvLzFIzrPgIBVHBqTFlNKFByZugaCZVCqRVuvbRYrSp
         dHmA9Xaxn/jwDPjlnqHcNIChUAUuclRsoozFCs+19+mNMGWfF8Y3O41QXo6potrwr3Y8
         iTSyPPDL+UFkqTfXcYO7IegrIb29SAHIAltkxIJ97yB/iJG1KBAl+USSYGuC81DvDWNE
         +Ipw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=ClCAE1gT;
       dkim=neutral (no key) header.i=@suse.cz header.b=4bUXNii3;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2001:67c:2178:6::1c])
        by gmr-mx.google.com with ESMTPS id bt2-20020a056000080200b002416691399csi305421wrb.4.2022.11.20.08.50.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 20 Nov 2022 08:50:25 -0800 (PST)
Received-SPF: softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1c as permitted sender) client-ip=2001:67c:2178:6::1c;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id C423D2234F;
	Sun, 20 Nov 2022 16:50:24 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 8C98813216;
	Sun, 20 Nov 2022 16:50:24 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id +1/FIdBaemOlWAAAMHmgww
	(envelope-from <vbabka@suse.cz>); Sun, 20 Nov 2022 16:50:24 +0000
Message-ID: <fd3211fd-5b3c-c1f2-c126-e96844b16c22@suse.cz>
Date: Sun, 20 Nov 2022 17:50:24 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.4.2
Subject: Re: [PATCH v2] mm: Make ksize() a reporting-only function
Content-Language: en-US
To: Kees Cook <keescook@chromium.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>, Christoph Lameter
 <cl@linux.com>, Pekka Enberg <penberg@kernel.org>,
 David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Roman Gushchin <roman.gushchin@linux.dev>,
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, Andrey Ryabinin
 <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>,
 Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>, linux-mm@kvack.org,
 kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
 linux-hardening@vger.kernel.org
References: <20221118035656.gonna.698-kees@kernel.org>
 <230127af-6c71-e51e-41a4-aa9547c2c847@suse.cz>
 <202211180907.A4C218F@keescook>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <202211180907.A4C218F@keescook>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=ClCAE1gT;       dkim=neutral
 (no key) header.i=@suse.cz header.b=4bUXNii3;       spf=softfail (google.com:
 domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1c
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

On 11/18/22 18:11, Kees Cook wrote:
> On Fri, Nov 18, 2022 at 11:32:36AM +0100, Vlastimil Babka wrote:
>> On 11/18/22 04:56, Kees Cook wrote:
>> > With all "silently resizing" callers of ksize() refactored, remove the
>> 
>> At cursory look seems it's true now in -next (but not mainline?) can you
>> confirm?
> 
> Almost, yes. I realized there is 1 case in the BPF verifier that
> remains. (I thought it was picked up, but only a prereq patch was.) I'm
> going to resend that one today, but I would expect it to be picked
> up soon. (But, yes, definitely not for mainline.)
> 
>> That would probably be safe enough to have slab.git expose this to -next now
>> and time a PR appropriately in the next merge window?
> 
> Possibly. I suspect syzkaller might trip KASAN on any larger BPF tests
> until I get the last one landed. And if you don't want to do the timing
> of the PR, I can carry this patch in my hardening tree, since I already
> have to do a two-part early/late-merge-window PR there.

OK I'm fine with you doing that, there's my ack already, hopefully Andrey is
now also happy :)

Vlastimil

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/fd3211fd-5b3c-c1f2-c126-e96844b16c22%40suse.cz.
