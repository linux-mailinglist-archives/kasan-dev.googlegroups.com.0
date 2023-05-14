Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBJ6UQKRQMGQEECYBT6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id B0EA4701C9A
	for <lists+kasan-dev@lfdr.de>; Sun, 14 May 2023 11:30:16 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id 2adb3069b0e04-4f12ff2cee7sf6066474e87.1
        for <lists+kasan-dev@lfdr.de>; Sun, 14 May 2023 02:30:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1684056616; cv=pass;
        d=google.com; s=arc-20160816;
        b=iYr8CtI0001sYYRZVQUr1lRnkViAfV/u/WCHWSg/5IhjPITSRsGNvJG4PzJ1+uVjHM
         VtGY8wpYPGwx9hOyLluxcK8mlSnc3m6sdb+PdONSzFTHf6Xzm7HsaxoF0A4/yh2LyiVJ
         dik5jZdzrjZuJeGkNA0OYLzRYQnCy/9+6/Rt4K7QynyWI4gGqveP/UULWzfTx0yCVQoq
         XW6MJIf74Kx+x1KJPU+DnOkLm0NGIRvjvH8uXsTVkvNz21ev5GzRmqOIy33PHxAtJqZr
         yibkL1AjKr2DzMDf+7qAMgj8jxSCi8xxmClXAwGpKP5Q0oQam/wyesAsdisyqV3aenBT
         eF2w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:references:cc:to:content-language:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature;
        bh=W8iZ07P2Q44YOX4zlTAAv6QsOClpNuXnYF1j0LVyGik=;
        b=0aaqpb04L0wErshTP+NBxpKr1WS7OO5Jc3fsDq/26E9dxvIqP7kzHiijF9kJiS0fH8
         7AA0pINAwX4kdfRCxiOHC0pJTAX8hpgUSjwVyVnl6Qwm4Ai0x1YNdjDW9c/TAcUdiorL
         4k4VfkSDA9kBmEfEL2Sh8RuuywfV1ZQcUZcqPbdWyN7obcmUl57pIIa8Qwt3BxWcTwzl
         C9nmcViIU04Otcq3iiLapyiDwKdJ1W76mSHfKrUhZ+1HN6YdrWZKPjq+XZUN1MJNSCBn
         VpILGutcUt0VrwaSA5tun9qs8FRc3lzdLrr//2FRrvRP4JN+wiQh4nQch2/FXPXyhxQm
         N4pA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=CTpsMPkb;
       dkim=neutral (no key) header.i=@suse.cz header.b=SJgsbtU9;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1684056616; x=1686648616;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=W8iZ07P2Q44YOX4zlTAAv6QsOClpNuXnYF1j0LVyGik=;
        b=ZXLOQbZPkQUykWvcoIvP83LuXgJ4HyJIndkXJ35DbwLZ75sj5lMumnNBHV+dE0dMA1
         vMjUYrzmPTaQLYestllsWnJObbCPMiVj2Djpa0EfuSEcaxTQz9HznCHRKElmwXnj8A1w
         8p0vzG0PiR52JV9FWOd0cuphGjiGhML11JQBey6W791Y3I5XCJoY4M+53uENJgmnj05l
         04bW2mpWaRdCIhlBiG6niU7JxwG2YYpY9QUF41gVis2z4SFazJhwx4uTTfsyY1awQE46
         2G/AUoQ4HT60XCRUSLvbfVZ/qJzDhqpr+AGy/ztkD0Br7bpyvBn+ZAagr2KIJb2R9hsa
         +JdA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1684056616; x=1686648616;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=W8iZ07P2Q44YOX4zlTAAv6QsOClpNuXnYF1j0LVyGik=;
        b=G7UuovmUZ+vMCG1G3NcHqAFu6Ltkw0q6K5BXuUhzyY+CpQhlBXWDCOjCcFRtDZWQe4
         kCGJv0nftdd6YWUj6NOl62Y2HAXnleO7MBCAd+Yf1VqRh9x+YjWAQ+QgfKX1zC13LJnH
         zUFAc8CsB89Q79s26/I7v1ocoB1hzqD9BRgpONSWo8HHvkJFfK2E9pjanMlXmBZIb45Q
         YJao1mc9JTTikxZhRg8eMzO2u1xNKdwlB/5wUk9D9trfTgTUGRTGupIIjIUyrOaw/kxh
         FQrTgPsCLVvJazAJOXmPFn9T0YtrV/5MCVbkh3dZMi9kvmxGhGhqLpKQOtCcfMmidfM6
         iw3Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDwm4mf8fvavCAkyKHF+lFG75E+8dvahuxDrGevVvTtrTX0c947C
	gyqGm/RP7cg8xNxiS9maN7A=
X-Google-Smtp-Source: ACHHUZ4S4dIhKANIXu2oIFijJpDqZUGTpVOvfummyw6TaidR6Q177Yu0Vwd/2T2lN8K0YB9KSRspWQ==
X-Received: by 2002:ac2:43cd:0:b0:4f1:3dca:a4f0 with SMTP id u13-20020ac243cd000000b004f13dcaa4f0mr4322058lfl.7.1684056615769;
        Sun, 14 May 2023 02:30:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:311c:b0:4f1:4c37:e1cc with SMTP id
 n28-20020a056512311c00b004f14c37e1ccls399438lfb.0.-pod-prod-07-eu; Sun, 14
 May 2023 02:30:14 -0700 (PDT)
X-Received: by 2002:a05:6512:41b:b0:4f1:34ac:531a with SMTP id u27-20020a056512041b00b004f134ac531amr5604110lfk.18.1684056614024;
        Sun, 14 May 2023 02:30:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1684056614; cv=none;
        d=google.com; s=arc-20160816;
        b=EyYnvdRm1j6mGzLWFOw2b3LxX8GfFDXsBjmj96dti2AMAime4rJQtBlOsEUHCYB/Ni
         pu9OSTXHP+ldU1q0WwHpHOPA9SZmr4/14WGt9li/ZiiXOWLZn4WoWN9xfj4R7kG0/2MV
         PSlWTDxQ6xy77nqwga/6gE+sg+cSVTpILg2sQskM6Ub8M68QmE2DyVFjHepIhv6YCBIS
         jG1h0GsrFCzkzRCQB+uWPnVXIi9yJdIXuhswxnN3PmTdZ7uWn+6nECjxtD/+mxAua9a1
         gk+5gw+Pc7ioYcTngB2if3bD/RLAwBzjBCnpq5NGnG2OIBdbpRsVT+J9QGZB5fmzmknE
         VBkQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=dHSZYYmiO6JSUTlgPd0JkN7TgOMKpr6vyTG9Hwy+Zzo=;
        b=wCAPWcMSbfDrzqCYmJg2TBnYwQN+Ef63rYu8vf01ddUQNUaBbfjZ2n7L8kxTy5myae
         gMLpnJB0tSF0xLNVVCh2ONWZBrMlbUoJud9hC03+4/0Xafn7Kb2LCBe1Av1PLBaxRdqZ
         Q8clCrD2GtM5OQS8E/aM1bjhmb/aQ5HSD0OMIoSzf4hBxRwf+F1EufRsCxlIsjHInM+F
         OxBxjs6Qldf/rbqdEAKdENaBbi4BHHbpqa410i4FttdonWSlnsXssutu9uChbuWswHUE
         MiSVTk7PEVzLzsRlD9KWtfAigBqXI0U3I6m0hh/ykwhk8MvRdVv7mgfZ1Zhgi6pfjz4b
         bvQA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=CTpsMPkb;
       dkim=neutral (no key) header.i=@suse.cz header.b=SJgsbtU9;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2001:67c:2178:6::1c])
        by gmr-mx.google.com with ESMTPS id j6-20020a056512398600b004f145238b58si898759lfu.4.2023.05.14.02.30.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 14 May 2023 02:30:13 -0700 (PDT)
Received-SPF: softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1c as permitted sender) client-ip=2001:67c:2178:6::1c;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 1CCB521FB9;
	Sun, 14 May 2023 09:30:13 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id B35D8138F5;
	Sun, 14 May 2023 09:30:12 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id dzHeKiSqYGRbUwAAMHmgww
	(envelope-from <vbabka@suse.cz>); Sun, 14 May 2023 09:30:12 +0000
Message-ID: <b9331fe4-11c8-5323-e757-5cae3c1e2233@suse.cz>
Date: Sun, 14 May 2023 11:30:30 +0200
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.10.1
Subject: Re: [PATCH RFC v2] Randomized slab caches for kmalloc()
Content-Language: en-US
To: Gong Ruiqi <gongruiqi1@huawei.com>, Hyeonggon Yoo <42.hyeyoo@gmail.com>
Cc: linux-mm@kvack.org, linux-kernel@vger.kernel.org,
 linux-hardening@vger.kernel.org,
 Alexander Lobakin <aleksander.lobakin@intel.com>,
 kasan-dev@googlegroups.com, Wang Weiyang <wangweiyang2@huawei.com>,
 Xiu Jianfeng <xiujianfeng@huawei.com>, Christoph Lameter <cl@linux.com>,
 David Rientjes <rientjes@google.com>,
 Roman Gushchin <roman.gushchin@linux.dev>,
 Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Andrew Morton <akpm@linux-foundation.org>, Pekka Enberg
 <penberg@kernel.org>, Kees Cook <keescook@chromium.org>,
 Paul Moore <paul@paul-moore.com>, James Morris <jmorris@namei.org>,
 "Serge E. Hallyn" <serge@hallyn.com>,
 "Gustavo A. R. Silva" <gustavoars@kernel.org>
References: <20230508075507.1720950-1-gongruiqi1@huawei.com>
 <CAB=+i9QxWL6ENDz_r1jPbiZsTUj1EE3u-j0uP6y_MxFSM9RerQ@mail.gmail.com>
 <5f5a858a-7017-5424-0fa0-db3b79e5d95e@huawei.com>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <5f5a858a-7017-5424-0fa0-db3b79e5d95e@huawei.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=CTpsMPkb;       dkim=neutral
 (no key) header.i=@suse.cz header.b=SJgsbtU9;       spf=softfail (google.com:
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

On 5/12/23 12:11, Gong Ruiqi wrote:
>=20
>=20
> On 2023/05/11 2:43, Hyeonggon Yoo wrote:
>> On Mon, May 8, 2023 at 12:53=E2=80=AFAM GONG, Ruiqi <gongruiqi1@huawei.c=
om> wrote:
>>>
>=20
> [...]
>=20
>>>
>>> The overhead of performance has been tested on a 40-core x86 server by
>>> comparing the results of `perf bench all` between the kernels with and
>>> without this patch based on the latest linux-next kernel, which shows
>>> minor difference. A subset of benchmarks are listed below:
>>>
>>
>> Please Cc maintainers/reviewers of corresponding subsystem in MAINTAINER=
S file.
>=20
> Okay, I've appended maintainers/reviewers of linux-hardening and
> security subsystem to the Cc list.

I think they were CC'd on v1 but didn't respond yet. I thought maybe if
I run into Kees at OSS, I will ask him about it, but didn't happen.

As a slab maintainer I don't mind adding such things if they don't
complicate the code excessively, and have no overhead when configured
out. This one would seem to be acceptable at first glance, although
maybe the CONFIG space is too wide, and the amount of #defines in
slab_common.c is also large (maybe there's a way to make it more
concise, maybe not).

But I don't have enough insight into hardening to decide if it's a
useful mitigation that people would enable, so I'd hope for hardening
folks to advise on that. Similar situation with freelist hardening in
the past, which was even actively pushed by Kees, IIRC.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/b9331fe4-11c8-5323-e757-5cae3c1e2233%40suse.cz.
