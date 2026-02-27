Return-Path: <kasan-dev+bncBAABBCFLQXGQMGQE4QMGPLI@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id iHRXFYpVoWk+sQQAu9opvQ
	(envelope-from <kasan-dev+bncBAABBCFLQXGQMGQE4QMGPLI@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Fri, 27 Feb 2026 09:27:54 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63c.google.com (mail-ej1-x63c.google.com [IPv6:2a00:1450:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id EAA251B4894
	for <lists+kasan-dev@lfdr.de>; Fri, 27 Feb 2026 09:27:53 +0100 (CET)
Received: by mail-ej1-x63c.google.com with SMTP id a640c23a62f3a-b8fa5744b82sf183878366b.3
        for <lists+kasan-dev@lfdr.de>; Fri, 27 Feb 2026 00:27:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1772180873; cv=pass;
        d=google.com; s=arc-20240605;
        b=MtWl16fZ7JASFtXFsngQ8gKeN7nfphyul5gCM7rclXhW3RwlHscQ0sucewJ3ZBqOaJ
         6HyCku6dggpdOLSm5N7BEOOoqmyt+9RgDl9lFsBcJAofxOFt+FHyYqKrFZoLKXxfOeoz
         jz15eRif9c8YB71j/uhrWZppRzs6UMzbjLnCUH2GZbrcnxHmWX3VGnSrFnrrUFzm5U5T
         kwf/BZTuk9YxZqx+OEZMq1g1Ar02mfzZ+ogfEYFAALd5LKILH9W4C/RY1WASc7h/3nxK
         gLZD9UdRD1/ABPiewMYfXTJ7qNJ2CriXQamQUY3tKQnYpN+tzLEy1WTZAyF5/dWVL93G
         vM9w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :mime-version:feedback-id:references:in-reply-to:message-id:subject
         :cc:from:to:date:dkim-signature;
        bh=h7KzAKn0A0VhWIfdgvJylsc9SoSkqig5puJ2Cbk6SzA=;
        fh=iMieCVJCELfgaovB2B8hTar7JHE19nl4gcDk++1jk+A=;
        b=ZSsCKB7rNMuOM6U2pwta8Bh0/t+6ZyzbMdtTtuwEBZ6DMPlJKuf7bqcUonHO0N2bkd
         5iF+0r1mUmg6NRBfHQQnha2wqD8N+vk6xDAqGCF2HruPeVQS/FBf7FZ+GoyYtwi8xNg7
         L5mXUCsI0PfQUas2BTdW6k3F/f8P2AR0l4WmE0VKscef2pp4MBlTfr2IuKdTw9aw3Igg
         4kIlptEZO9cl066EIvg2RfI65szZfDxzGQvTIXrCY61EgX2wZsKOk2CSnxTtWa2Q/peT
         lhqm3S0p/79LBnOMfacZUZ2deF/Fcgv3ZKPlxQB8PmLM2snlWD00Yn3W1h3p+pBwZu1f
         s7sg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=BUbKSCA8;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.29 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1772180873; x=1772785673; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=h7KzAKn0A0VhWIfdgvJylsc9SoSkqig5puJ2Cbk6SzA=;
        b=h5zGXvM7xfQHf+R+vJVgfpj1YTK210G077TDl97VP4blY1hTvRhJiEM02pJ9/sCYBq
         qG1YKZz8JTNiF7xPa5i+wWIAhJBCFFBGaTH1dRvLhQ3EwkWvQcDVcnXka7mnNKmO9zGR
         aaRshA2Kc+BRBYAupz8mdo0IyoBkBrAt8HjA5wcWm9+HEEitmrsiM0IcGHcw+3OKf951
         zexEqrH1WB2t1po6L4M4410fbiJ3yHbFo6U1CNOPXnZL0KjILZN6AD70icbH+9RlY2P4
         UTSTTbUFreH8zDl/nuTlffJzd1mHHH2gtltPdnXqdF16/u2nazbWMwW6Q0zDfb12/jBH
         tCpA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1772180873; x=1772785673;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=h7KzAKn0A0VhWIfdgvJylsc9SoSkqig5puJ2Cbk6SzA=;
        b=Db4N6gciDdNyGKFBefeQvKTyM1NBrHTiXz79eyb9DLBuFRibmFMmvUvwZTwuipgYGA
         8qW5knoEansNSWCCfUGOoIT/dxb/xfLN/51c96yJK9omsiPPZ5czLTmWLHZVMEoUgV65
         Qyd2jf48JPK1vVFagmYK9p6I6YPnWtte8Re8PbFRFUE1hpEfqfpv6fjZpG0IVArJgSx4
         8/C5amYTYBOKcReXF8u9epugS/NPYeT2Wc/GM1EO3t+mxrwci2bWO9XIvGXZYTznMPDs
         BXkB1fc2i5FPpdqcrQkbTxW5F55eYdeQ2Kgu0tH124kwIJ57alOZ6Qq6Phj8uu6u/hYh
         hU5w==
X-Forwarded-Encrypted: i=2; AJvYcCXlVfTSq6nwje/W5WOZBdszoDnVif1gkB+N8yBvKxucJIWAdUElTsTszh3kbOjxB7RiITmrHQ==@lfdr.de
X-Gm-Message-State: AOJu0YzwZpLYaMaquAcEZP/TuAJ1Uz9YuWdD0jlrpyZZJyCOVOymmPFP
	xD10C9KoF6R3iRJLrV5GSb5AaUZUtdaQ5uMk0l2+F+AmMtxB3MqMYUac
X-Received: by 2002:a05:6402:1456:b0:65c:2125:f047 with SMTP id 4fb4d7f45d1cf-65fdd6bcc6bmr1322823a12.5.1772180873002;
        Fri, 27 Feb 2026 00:27:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+EBZOh8YdglG4EbxQQFdFIiB8LXztcPspPqYy5oJMDzxw=="
Received: by 2002:aa7:de06:0:b0:65f:71e6:9fb3 with SMTP id 4fb4d7f45d1cf-65f88d12c97ls2189244a12.1.-pod-prod-06-eu;
 Fri, 27 Feb 2026 00:27:51 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUMF5i5WMz0mkczU865vmbwhG58WfEs8ZEVaqUm3L66/Oc54/Wof25zQ1JxZcUwbZ913/t3I58up6Q=@googlegroups.com
X-Received: by 2002:a05:6402:27cc:b0:65b:fa9f:fce4 with SMTP id 4fb4d7f45d1cf-65fddee5871mr1136056a12.27.1772180871169;
        Fri, 27 Feb 2026 00:27:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1772180871; cv=none;
        d=google.com; s=arc-20240605;
        b=A2go/rXV/6ircm5uicmsdoNEbBIuIDW8TUDYAtoeUSdkd7WV5EG9dTaGgaRGSjOPzd
         ca/9EY8qep8MJVckbtiGN5VpUgeiAqzyYv/DWws4fhyFFmawdv4VIZlD6NRVk6TzY/T1
         ZGFjnqPw5p9/yUMF5Hw7GcOZhPV4HTZH2eVO/KmX10uBslvutBEEg4nDrM/78FFSmByN
         9sZw/TzvOnzEXLLvlMNcx8tTwbxpKpVbERXMn+wEaOTUQpyH3m0YuOq/ISzyk82Oruuo
         l/lWlyruXAtNNDXegB0/VxT0jeyWVRMiISVl/zoNFk3A0Ca74uS+u5ibiJf5wNcXsjjv
         0vdA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=w1GCmvI9nDdcfpwv/EBNLFU8kur4WRAZzbZH+/hHGr4=;
        fh=RX1FTpF6ubPqdGvhXch2v/H0LMQINDgb+rxI7yVCgzc=;
        b=NxllrR/Oqw8jVNCgMqD32TAD00EXDwskk2Gm2EQDc6boll2wIb6crob6hLkRgtvM6b
         +R0U7jUWIB0qh6Kp5M3oJpi9nBEhvH8QIeuzu7r+d0IpJUaHcfNLyr3nlZyk1sqnN9Go
         i9oUgt1XMvoYZ97N/DkL3eW+cITBXlN/XfGBO0OkmVN2lU0zsLSg+ZCpolBpSd2uUMsO
         3XPJ8h2qUxPIbYgxaGDtbNuRuiLpn+uT9X6Xwd57lHDLI6sAyo6shSsk424w3eRCdJ9V
         ZnmH5eIZmEdZ+h8xJmJ2H1HGuwu3/pGWcPhVXTB/XW6VZKZWEP7OVAnyS8loxj4LUHVz
         Cwig==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=BUbKSCA8;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.29 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-10629.protonmail.ch (mail-10629.protonmail.ch. [79.135.106.29])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-65fac07d6d0si128187a12.8.2026.02.27.00.27.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 27 Feb 2026 00:27:51 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.29 as permitted sender) client-ip=79.135.106.29;
Date: Fri, 27 Feb 2026 08:27:44 +0000
To: Dave Hansen <dave.hansen@intel.com>
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: Thomas Gleixner <tglx@kernel.org>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, "H. Peter Anvin" <hpa@zytor.com>, Jonathan Corbet <corbet@lwn.net>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, Andy Lutomirski <luto@kernel.org>, Peter Zijlstra <peterz@infradead.org>, Andrew Morton <akpm@linux-foundation.org>, Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, linux-kernel@vger.kernel.org, linux-doc@vger.kernel.org, kasan-dev@googlegroups.com, workflows@vger.kernel.org
Subject: Re: [PATCH v10 13/13] x86/kasan: Make software tag-based kasan available
Message-ID: <aaFVCivIQ1kjKhUZ@wieczorr-mobl1.localdomain>
In-Reply-To: <fb8d8d51-66c8-4cb1-8b14-bc670c629afa@intel.com>
References: <cover.1770232424.git.m.wieczorretman@pm.me> <8fd6275f980b90c62ddcb58cfbc78796c9fa7740.1770232424.git.m.wieczorretman@pm.me> <f25c328f-4ce7-4494-a200-af4ba928e724@intel.com> <aZ1qOpMc9PohArcL@wieczorr-mobl1.localdomain> <fb8d8d51-66c8-4cb1-8b14-bc670c629afa@intel.com>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 98763143edaccaef44e93295f566fd10be419899
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=BUbKSCA8;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.29 as
 permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
X-Original-From: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Reply-To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-0.71 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36];
	MAILLIST(-0.20)[googlegroups];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	TAGGED_FROM(0.00)[bncBAABBCFLQXGQMGQE4QMGPLI];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_CC(0.00)[kernel.org,redhat.com,alien8.de,linux.intel.com,zytor.com,lwn.net,gmail.com,google.com,arm.com,infradead.org,linux-foundation.org,intel.com,vger.kernel.org,googlegroups.com];
	RCVD_COUNT_THREE(0.00)[3];
	RCPT_COUNT_TWELVE(0.00)[21];
	MIME_TRACE(0.00)[0:+];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	TO_DN_SOME(0.00)[];
	NEURAL_HAM(-0.00)[-0.990];
	FROM_EQ_ENVFROM(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev];
	MISSING_XM_UA(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	HAS_REPLYTO(0.00)[m.wieczorretman@pm.me]
X-Rspamd-Queue-Id: EAA251B4894
X-Rspamd-Action: no action

On 2026-02-26 at 15:29:15 -0800, Dave Hansen wrote:
>On 2/24/26 01:10, Maciej Wieczor-Retman wrote:
>>>> -   ffdf000000000000 |   -8.25 PB | fffffbffffffffff |   ~8 PB | KASAN=
 shadow memory
>>>> +   ffdf000000000000 |   -8.25 PB | fffffbffffffffff |   ~8 PB | KASAN=
 shadow memory (generic mode)
>>>> +   ffeffc0000000000 |   -6    PB | fffffbffffffffff |    4 PB | KASAN=
 shadow memory (software tag-based mode)
>>>>    __________________|____________|__________________|_________|______=
______________________________________________________
>>> I think the idea of these is that you can run through, find *one* range
>>> and know what a given address maps to. This adds overlapping ranges.
>>> Could you make it clear that part of the area is "generic mode" only an=
d
>>> the other part is for generic mode and for "software tag-based mode"?
>> Boris suggested adding a footnote to clarify these are alternative range=
s [1].
>> Perhaps I can add a star '*' next to these two so it can notify someone =
to look for
>> the footnote?
>>
>> [1] https://lore.kernel.org/
>> all/20260113161047.GNaWZuh21aoxqtTNXS@fat_crate.local/
>
>
>I'd rather this be:
>
>  ffdf000000000000 |   -8.25 PB | fffffbffffffffff |   ~8 PB | KASAN shado=
w memory[1]
>
>...
>
>1. talk about the ranges here. Maybe: Addresses <ffeffc0000000000 are used=
 by
>   KASAN "generic mode" only. Addresses >=3Dffeffc0000000000 can additiona=
lly
>   be used by the software tag-based mode.
>
>Or, list both ranges as separate:
>
>  ffdf000000000000 |   -8.25 PB | ffeffbffffffffff |   ~8 PB | KASAN shado=
w memory (generic mode only)
>  ffeffc0000000000 |   -6    PB | fffffbffffffffff |    4 PB | KASAN shado=
w memory (generic or
>										    software tag-based)
>and describe the same use (generic mode) twice.

Thanks, I like the first option, I'll work on that.

--=20
Kind regards
Maciej Wiecz=C3=B3r-Retman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
aFVCivIQ1kjKhUZ%40wieczorr-mobl1.localdomain.
