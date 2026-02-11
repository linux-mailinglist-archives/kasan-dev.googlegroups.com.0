Return-Path: <kasan-dev+bncBDOLFNPTXIORBZFVWHGAMGQEATJLT6A@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id GPwyNudajGkOlwAAu9opvQ
	(envelope-from <kasan-dev+bncBDOLFNPTXIORBZFVWHGAMGQEATJLT6A@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Feb 2026 11:33:11 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 248CC123691
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Feb 2026 11:33:10 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id 2adb3069b0e04-59e53b0ffa5sf1352184e87.1
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Feb 2026 02:33:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1770805990; cv=pass;
        d=google.com; s=arc-20240605;
        b=Q38uDD4LuN2oJJr3EZkJvXFpcVRY5Pf+NX1tanP+/s6OJaz/fMjAeKbb06fqfMtYrh
         bh55CFkFovAVHy4swXyLENAfQM01DtE0URskaxTrCOx4qBXdUFft149jPqcdEED0Dugr
         k5jCsAq0swlYl2fDA+hoAkbKRKHX83woFtd/doyJKdLCJ9nYVnMPgjdN+3+kzkn7Doe/
         4ALkTAErWCOf6fd9V1HdKVip4ggh987nfzAxwBbdP0Xp1YtJ2+tuVS0bratfQKrDwdFF
         LZzkKl/ZUBylXn5VdpZOwsMnucg43uYy6eAyyTMXtmTw3zjfXAGAyGBpXQ1ehdVSkvWn
         QY2w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:user-agent:references:in-reply-to:subject:cc:to:from
         :message-id:date:sender:dkim-signature;
        bh=NQqNFzChnugTCQ6GTbo/Z0SN8xUPsl+t9/GjsiIvnyc=;
        fh=MJFyJIubrSgqom53xVr7/L7ZeHlvsg2ULlTHmEbDxPo=;
        b=lkeB7x7qJAki3WHHtVEmMKnz7Vn7v0B+LTo5hkI1f5cExL547omMJqnSZPObZBl9Kj
         F15QvUtfvv/GLiUtMkOkcfCelGAt7icxjWCzbh3/mAzYspHHkYBsL0M56GFjASVVRyGS
         YHEBNtL1d5Z1GWIvts64ScMqFzBA6nRrvFxd6zZZ94xrJP85brKhOzPPlV3+NV257BKC
         3lqXF3JNkAqe1WRPGN6gyKpgaJ6HxUW8Q7TcAObYhnBnxoQETdCcW+E100D3sY2oAXvk
         eJLXY2cqdS0iLm7hcUn4vjByn1HahpiNaXXVe2Azpg7l7fUb6zh6u/kkcdV8qXtsKZyQ
         UKFQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=U7PRbHY8;
       dkim=neutral (no key) header.i=@suse.de;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=U7PRbHY8;
       dkim=neutral (no key) header.i=@suse.de;
       spf=pass (google.com: domain of tiwai@suse.de designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=tiwai@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1770805990; x=1771410790; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:references:in-reply-to:subject:cc:to:from:message-id
         :date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=NQqNFzChnugTCQ6GTbo/Z0SN8xUPsl+t9/GjsiIvnyc=;
        b=r7JQclZWO+eZ70CE4eKBzMf2yVnOy/GpwksesnhoqEqJORfwMG0dEzqn6n275UrVjr
         8mVK2jU9FHpylVjzNG/eH4xyksPnireStbdgHhUet82hOKVOGwqSjjHlJ23i/10LjPhV
         Gztb7k2ggc6TwUiD+e+isTjDLrG7JJxiNyPUYq3EvmGTLvOG6RRfKmrGFNAn9PGo7319
         lTqBT09UFalpHEOokaEv62J7b3T/ZA1sZKyd15UwLr+lPuh5qjcW4GwZeFs3NI+LDyzF
         ij3dhcrLlckO8InYf54tBcKmPSte5Q22fxHWtNBhdd4uiPsPYXkxR4VH6XYcmUGbjJrI
         fQuQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1770805990; x=1771410790;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :content-transfer-encoding:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:references:in-reply-to
         :subject:cc:to:from:message-id:date:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=NQqNFzChnugTCQ6GTbo/Z0SN8xUPsl+t9/GjsiIvnyc=;
        b=ZfM3joCaQWG3fwC1haeCUvDQ0mcH0aJeUcfl9bsA9ox4aJ54f7pInjGwutIOOxjZOk
         Ge12XZSNM8QQh06jaqb9zarFHDoYVdWllsK8xdBddGvcmtPtAjipuljpDe38tS4SjGu0
         Y2VT18NqRhLt7QS/iTcU+soJKiWqdgGhA7cZiN3184L1OfiubsG9DRx95yutn/ftb4Fy
         35n+ciy9W1mfojBH8tuxm8Eu1kwiQiCIPZWeycuX0/azimRzDNySLUvz9MpRwBkhbMWK
         UcWigsQnGm9oGGLqJBEpUgdlkSymjxVdtLqjEVh1UJCzxhqoDTlHiYVJQbLKSqXH1EOt
         aQTg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVcX9KAnlDQS28q16JVhj/qgFbSuF3JO6ZEn1iSdo59+bRIclXGTLvhHk0u3Ev0ah2aVzZjcg==@lfdr.de
X-Gm-Message-State: AOJu0YwOly7USUNAKOk4pRGfJ8GHAFyCHjT9L+agMkwBoKj7Lewy8G0k
	NhpZLwel4YkITHZDnD7JrMtH5jgy2oejvpt9RRVzLOBXNl3K9WJIXv2X
X-Received: by 2002:ac2:4c4e:0:b0:59e:1954:1d4d with SMTP id 2adb3069b0e04-59e5df466ffmr547272e87.7.1770805989691;
        Wed, 11 Feb 2026 02:33:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FLx4TIDYAMKEuiUVx8Sbv9jYm5cXeiyQSr4HjPF3xrsA=="
Received: by 2002:a05:6512:3b99:b0:59b:a3bb:9e0f with SMTP id
 2adb3069b0e04-59e3c47e64als2317166e87.2.-pod-prod-01-eu; Wed, 11 Feb 2026
 02:33:06 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU9KwJrOfdRoHOoMHra59PwBkE2iFkSIx0xVEqc5x3BLXpi9nwHlGIeBGvc1T23nD6Egfhj3WbwWt8=@googlegroups.com
X-Received: by 2002:a05:6512:220e:b0:59d:e9df:c101 with SMTP id 2adb3069b0e04-59e5e06d9famr533293e87.26.1770805986284;
        Wed, 11 Feb 2026 02:33:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1770805986; cv=none;
        d=google.com; s=arc-20240605;
        b=eNTjiMt1gYLu0GJXqxbZEazOdkNHCvXpUn1HYr7yv4n7uEeWvZLHA+LxEWJKU0ljCt
         PflDgXRj8loFPkOIlWOqO7ZvurXbzvKOPvO5eyIyzCDUjSabjqByk+ekv4wGP75GzpaD
         SSoTs/fP5w0u3ucLCW4yxNxg127pafL60Xh50RCWDSxJG4UDXaC9OzVJ41ge3lUztd3s
         a4vXtdaIbTAA3rKDKoCptYC0acaCJ4E41HqY23V+mHDVIzfShngq5l5S/iXbIVXPlX7K
         nAjFo8xzpvSDsAsww5yIqjKGZnXVaI10Ch995IRhAuJYgJTrZ5ajbTr552yepwnzibxS
         BmUQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:user-agent:references:in-reply-to:subject:cc:to:from
         :message-id:date:dkim-signature:dkim-signature:dkim-signature
         :dkim-signature;
        bh=fuaM3HdeKUPerQ0jxZXZZPlq4it5iX6lCBVZ/FmlUZ8=;
        fh=MWdgKlpWIJZe29ZRK9JSaablYEqEqaF00eHHeDTx3Q8=;
        b=lLweNMSNY/nzsGwditTJ66bPzGo8KcJ6Rn4x/r+jQqk7zF0WgWl7zAMdkfWYvGFzLB
         rSUrxt1/SUehdjnicjtRpnwPpGh/ZQF+asR6k6PpJv7wyhH7zYH/eLS21SLuO3pyQZnq
         yfjRiahx14myOEF5FGfUZhRfVm7DeCgTsPFWQBFUWZrQnQE5jTsSBzFgq1Fg4+JKqUuK
         V0nxEbGjpmz5Hi0REcOzxI09EvOWB+lSTAxIyy43h0n7S6PsK8eT0B/bQfy/3L22pgBI
         i4O01Cbi7wgwEgk2VLWkgmNZauG0ZUvgWbVb5ImE8uRPwctZex7Pr77H+69c1w2Nb3YG
         7fiA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=U7PRbHY8;
       dkim=neutral (no key) header.i=@suse.de;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=U7PRbHY8;
       dkim=neutral (no key) header.i=@suse.de;
       spf=pass (google.com: domain of tiwai@suse.de designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=tiwai@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-59e5f59f11esi19767e87.6.2026.02.11.02.33.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 11 Feb 2026 02:33:06 -0800 (PST)
Received-SPF: pass (google.com: domain of tiwai@suse.de designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 3EEE03E73F;
	Wed, 11 Feb 2026 10:33:05 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id B786E139F2;
	Wed, 11 Feb 2026 10:33:04 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id edNlK+BajGmpRwAAD6G6ig
	(envelope-from <tiwai@suse.de>); Wed, 11 Feb 2026 10:33:04 +0000
Date: Wed, 11 Feb 2026 11:33:04 +0100
Message-ID: <87fr77tvrz.wl-tiwai@suse.de>
From: Takashi Iwai <tiwai@suse.de>
To: Thomas Gleixner <tglx@kernel.org>
Cc: Shinichiro Kawasaki <shinichiro.kawasaki@wdc.com>,
	Linus Torvalds
 <torvalds@linux-foundation.org>,
	LKML <linux-kernel@vger.kernel.org>,
	Ihor Solodrai
 <ihor.solodrai@linux.dev>,
	Shrikanth Hegde <sshegde@linux.ibm.com>,
	Peter
 Zijlstra <peterz@infradead.org>,
	Mathieu Desnoyers
 <mathieu.desnoyers@efficios.com>,
	Michael Jeanson <mjeanson@efficios.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko
 <glider@google.com>,
	"kasan-dev@googlegroups.com"
 <kasan-dev@googlegroups.com>
Subject: Re: [PATCH] sched/mmcid: Don't assume CID is CPU owned on mode switch
In-Reply-To: <87tsvoa7to.ffs@tglx>
References: <20260201192234.380608594@kernel.org>
	<20260201192835.032221009@kernel.org>
	<aYrewLd7QNiPUJT1@shinmob>
	<873438c1zc.ffs@tglx>
	<aYsZrixn9b6s_2zL@shinmob>
	<87wm0kafk2.ffs@tglx>
	<aYtE2xHG2A8DWWmD@shinmob>
	<87tsvoa7to.ffs@tglx>
User-Agent: Wanderlust/2.15.9 (Almost Unreal) Emacs/30.2 Mule/6.0
MIME-Version: 1.0 (generated by SEMI-EPG 1.14.7 - "Harue")
Content-Type: text/plain; charset="UTF-8"
X-Spam-Score: -2.01
X-Spam-Level: 
X-Spam-Flag: NO
X-Original-Sender: tiwai@suse.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.de header.s=susede2_rsa header.b=U7PRbHY8;       dkim=neutral
 (no key) header.i=@suse.de;       dkim=pass header.i=@suse.de
 header.s=susede2_rsa header.b=U7PRbHY8;       dkim=neutral (no key)
 header.i=@suse.de;       spf=pass (google.com: domain of tiwai@suse.de
 designates 2a07:de40:b251:101:10:150:64:1 as permitted sender)
 smtp.mailfrom=tiwai@suse.de;       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
Content-Transfer-Encoding: quoted-printable
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
X-Spamd-Result: default: False [0.89 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	MID_CONTAINS_FROM(1.00)[];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36];
	MAILLIST(-0.20)[googlegroups];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MIME_GOOD(-0.10)[text/plain];
	DMARC_POLICY_SOFTFAIL(0.10)[suse.de : SPF not aligned (relaxed), DKIM not aligned (relaxed),none];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_FROM(0.00)[bncBDOLFNPTXIORBZFVWHGAMGQEATJLT6A];
	RCVD_TLS_LAST(0.00)[];
	FORGED_SENDER_MAILLIST(0.00)[];
	MIME_TRACE(0.00)[0:+];
	TO_DN_EQ_ADDR_SOME(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[12];
	FREEMAIL_CC(0.00)[wdc.com,linux-foundation.org,vger.kernel.org,linux.dev,linux.ibm.com,infradead.org,efficios.com,gmail.com,google.com,googlegroups.com];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	TO_DN_SOME(0.00)[];
	FROM_NEQ_ENVFROM(0.00)[tiwai@suse.de,kasan-dev@googlegroups.com];
	FROM_HAS_DN(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	RCVD_COUNT_FIVE(0.00)[6];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,suse.de:mid]
X-Rspamd-Queue-Id: 248CC123691
X-Rspamd-Action: no action

On Tue, 10 Feb 2026 17:20:51 +0100,
Thomas Gleixner wrote:
>=20
> Shinichiro reported a KASAN UAF, which is actually an out of bounds acces=
s
> in the MMCID management code.
>=20
>    CPU0						CPU1
>    						T1 runs in userspace
>    T0: fork(T4) -> Switch to per CPU CID mode
>          fixup() set MM_CID_TRANSIT on T1/CPU1
>    T4 exit()
>    T3 exit()
>    T2 exit()
> 						T1 exit() switch to per task mode
> 						 ---> Out of bounds access.
>=20
> As T1 has not scheduled after T0 set the TRANSIT bit, it exits with the
> TRANSIT bit set. sched_mm_cid_remove_user() clears the TRANSIT bit in
> the task and drops the CID, but it does not touch the per CPU storage.
> That's functionally correct because a CID is only owned by the CPU when
> the ONCPU bit is set, which is mutually exclusive with the TRANSIT flag.
>=20
> Now sched_mm_cid_exit() assumes that the CID is CPU owned because the
> prior mode was per CPU. It invokes mm_drop_cid_on_cpu() which clears the
> not set ONCPU bit and then invokes clear_bit() with an insanely large
> bit number because TRANSIT is set (bit 29).
>=20
> Prevent that by actually validating that the CID is CPU owned in
> mm_drop_cid_on_cpu().
>=20
> Fixes: 007d84287c74 ("sched/mmcid: Drop per CPU CID immediately when swit=
ching to per task mode")
> Reported-by: Shinichiro Kawasaki <shinichiro.kawasaki@wdc.com>
> Signed-off-by: Thomas Gleixner <tglx@kernel.org>
> Tested-by: Shinichiro Kawasaki <shinichiro.kawasaki@wdc.com>
> Cc: stable@vger.kernel.org
> Closes: https://lore.kernel.org/aYsZrixn9b6s_2zL@shinmob

FWIW, I actually hit this bug yesterday on my laptop with 6.19 kernel,
so it's not only theoretical.

---- 8< ----
Feb 10 12:35:20 valkyrie kernel: BUG: unable to handle page fault for addre=
ss: ffff8ec348b322d0
Feb 10 12:35:20 valkyrie kernel: #PF: supervisor write access in kernel mod=
e
Feb 10 12:35:20 valkyrie kernel: #PF: error_code(0x0003) - permissions viol=
ation
Feb 10 12:35:20 valkyrie kernel: PGD 345801067 P4D 345801067 PUD 107790063 =
PMD 146391063 PTE 8000000148b32121
Feb 10 12:35:20 valkyrie kernel: Oops: Oops: 0003 [#1] SMP NOPTI
Feb 10 12:35:20 valkyrie kernel: CPU: 5 UID: 1000 PID: 17173 Comm: git Tain=
ted: G            E       6.19.0-test+ #679 PREEMPT(voluntary)  18755027502=
f5b378a0509f6d0a6ba52d8674d8b
Feb 10 12:35:20 valkyrie kernel: Tainted: [E]=3DUNSIGNED_MODULE
Feb 10 12:35:20 valkyrie kernel: Hardware name: LENOVO 21M2S03K00/21M2S03K0=
0, BIOS R2NET42W (1.16 ) 10/10/2025
Feb 10 12:35:20 valkyrie kernel: RIP: 0010:sched_mm_cid_exit+0xdf/0x1f0
Feb 10 12:35:20 valkyrie kernel: Code: 48 03 05 8c e9 48 02 8b 08 81 e1 ff =
ff ff bf 89 08 8b 05 34 74 b7 01 83 c0 3f c1 e8 03 25 f8 ff ff 1f 48 8d 84 =
43 c0 06 00 00 <f0> 48 0f b3 08 48 81 fe ff ef ff ff 77 08 48 89 d7 e8 4b a=
7 cc 00
Feb 10 12:35:20 valkyrie kernel: RSP: 0018:ffffd4358bea3c08 EFLAGS: 0001000=
2
Feb 10 12:35:20 valkyrie kernel: RAX: ffff8ec344b322d0 RBX: ffff8ec344b31c0=
0 RCX: 0000000020000008
Feb 10 12:35:20 valkyrie kernel: RDX: ffff8ec344b31d10 RSI: ffff8ec344b31d0=
f RDI: 0000000000000007
Feb 10 12:35:20 valkyrie kernel: RBP: 0000000000000000 R08: 000000000000001=
0 R09: 0000000000000001
Feb 10 12:35:20 valkyrie kernel: R10: 0000000000000000 R11: 000000000000000=
0 R12: 0000000000000000
Feb 10 12:35:20 valkyrie kernel: R13: ffff8ec370e76300 R14: ffff8ec30c10000=
0 R15: 0000000000000000
Feb 10 12:35:20 valkyrie kernel: FS:  00007f7e95e956c0(0000) GS:ffff8ed2920=
88000(0000) knlGS:0000000000000000
Feb 10 12:35:20 valkyrie kernel: CS:  0010 DS: 0000 ES: 0000 CR0: 000000008=
0050033
Feb 10 12:35:20 valkyrie kernel: CR2: ffff8ec348b322d0 CR3: 0000000108f7b00=
0 CR4: 0000000000f50ef0
Feb 10 12:35:20 valkyrie kernel: PKRU: 55555554
Feb 10 12:35:20 valkyrie kernel: Call Trace:
Feb 10 12:35:20 valkyrie kernel:  <TASK>
Feb 10 12:35:20 valkyrie kernel:  do_exit+0xad/0xa70
Feb 10 12:35:20 valkyrie kernel:  __x64_sys_exit+0x1b/0x20
Feb 10 12:35:20 valkyrie kernel:  x64_sys_call+0x1502/0x1510
Feb 10 12:35:20 valkyrie kernel:  do_syscall_64+0x81/0x650
Feb 10 12:35:20 valkyrie kernel:  ? do_syscall_64+0x81/0x650
Feb 10 12:35:20 valkyrie kernel:  ? __do_sys_newfstatat+0x32/0x60
Feb 10 12:35:20 valkyrie kernel:  ? do_syscall_64+0x81/0x650
Feb 10 12:35:20 valkyrie kernel:  ? do_syscall_64+0x81/0x650
Feb 10 12:35:20 valkyrie kernel:  ? do_syscall_64+0x81/0x650
Feb 10 12:35:20 valkyrie kernel:  ? do_syscall_64+0x81/0x650
Feb 10 12:35:20 valkyrie kernel:  ? do_syscall_64+0x81/0x650
Feb 10 12:35:20 valkyrie kernel:  ? do_syscall_64+0x81/0x650
Feb 10 12:35:20 valkyrie kernel:  ? __irq_exit_rcu+0x3d/0xe0
Feb 10 12:35:20 valkyrie kernel:  entry_SYSCALL_64_after_hwframe+0x76/0x7e
Feb 10 12:35:20 valkyrie kernel: RIP: 0033:0x7f7ea21de556
Feb 10 12:35:20 valkyrie kernel: Code: 8b 44 24 08 31 c9 48 89 88 20 06 00 =
00 31 c0 87 03 83 e8 01 7f 16 ba 3c 00 00 00 66 0f 1f 84 00 00 00 00 00 31 =
ff 89 d0 0f 05 <eb> f8 48 89 df e8 be cd ff ff 83 ed 01 0f 85 aa fd ff ff e=
b d7 48
Feb 10 12:35:20 valkyrie kernel: RSP: 002b:00007f7e95e94ee0 EFLAGS: 0000024=
6 ORIG_RAX: 000000000000003c
Feb 10 12:35:20 valkyrie kernel: RAX: ffffffffffffffda RBX: 00007f7e95e95cd=
c RCX: 00007f7ea21de556
Feb 10 12:35:20 valkyrie kernel: RDX: 000000000000003c RSI: 000000000080000=
0 RDI: 0000000000000000
Feb 10 12:35:20 valkyrie kernel: RBP: 00007f7e95695000 R08: 00000000000000c=
a R09: 0000000000000007
Feb 10 12:35:20 valkyrie kernel: R10: 0000000000000008 R11: 000000000000024=
6 R12: 0000000000801000
Feb 10 12:35:20 valkyrie kernel: R13: 0000000000000000 R14: 00007ffcf5038cc=
0 R15: 00007f7e95695000
Feb 10 12:35:20 valkyrie kernel:  </TASK>
Feb 10 12:35:20 valkyrie kernel: Modules linked in: tun(E) ccm(E) michael_m=
ic(E) rfcomm(E) snd_seq_dummy(E) snd_hrtimer(E) snd_seq(E) snd_seq_device(E=
) nft_fib_inet(E) nft_fib_ipv4(E) nft_fib_ipv6(E) nft_fib(E) nft_reject_ine=
t(E) nf_reject_ipv4(E) nf_reject_ipv6(E) nft_reject(E) nft_ct(E) af_packet(=
E) nft_chain_nat(E) nf_nat(E) nf_conntrack(E) nf_defrag_ipv6(E) nf_defrag_i=
pv4(E) cmac(E) algif_hash(E) algif_skcipher(E) af_alg(E) ip_set(E) bnep(E) =
binfmt_misc(E) nls_iso8859_1(E) nls_cp437(E) vfat(E) fat(E) qrtr_mhi(E) snd=
_acp_legacy_mach(E) snd_acp_mach(E) snd_soc_nau8821(E) snd_acp3x_rn(E) snd_=
acp70(E) snd_acp_i2s(E) snd_acp_pdm(E) snd_soc_dmic(E) snd_acp_pcm(E) snd_s=
of_amd_acp70(E) snd_sof_amd_acp63(E) snd_sof_amd_vangogh(E) snd_sof_amd_rem=
brandt(E) snd_sof_amd_renoir(E) snd_sof_amd_acp(E) snd_sof_pci(E) snd_sof_x=
tensa_dsp(E) snd_ctl_led(E) snd_sof(E) snd_hda_codec_alc269(E) snd_sof_util=
s(E) snd_hda_scodec_component(E) snd_pci_ps(E) snd_hda_codec_realtek_lib(E)=
 snd_soc_acpi_amd_match
 (E) snd_soc_acpi_amd_sdca_quirks(E)
Feb 10 12:35:20 valkyrie kernel:  snd_hda_codec_generic(E) snd_soc_sdca(E) =
snd_hda_codec_atihdmi(E) snd_hda_codec_hdmi(E) qrtr(E) snd_soc_core(E) inte=
l_rapl_msr(E) amd_atl(E) snd_hda_intel(E) snd_compress(E) intel_rapl_common=
(E) btusb(E) snd_rpl_pci_acp6x(E) btrtl(E) ath12k(E) snd_hda_codec(E) snd_a=
cp_pci(E) btintel(E) snd_intel_dspcfg(E) btbcm(E) uvcvideo(E) snd_amd_acpi_=
mach(E) mhi(E) snd_hda_core(E) btmtk(E) videobuf2_vmalloc(E) snd_acp_legacy=
_common(E) kvm_amd(E) videobuf2_memops(E) qmi_helpers(E) snd_pci_acp6x(E) s=
pd5118(E) bluetooth(E) snd_hwdep(E) uvc(E) kvm(E) snd_pci_acp5x(E) videobuf=
2_v4l2(E) mac80211(E) amd_pmf(E) think_lmi(E) snd_pcm(E) thinkpad_acpi(E) v=
ideodev(E) snd_rn_pci_acp3x(E) irqbypass(E) amdtee(E) libarc4(E) snd_acp_co=
nfig(E) sparse_keymap(E) snd_timer(E) snd_soc_acpi(E) i2c_piix4(E) videobuf=
2_common(E) platform_profile(E) pcspkr(E) mc(E) wmi_bmof(E) firmware_attrib=
utes_class(E) snd(E) tiny_power_button(E) cfg80211(E) snd_pci_acp3x(E) soun=
dcore(E) k10temp(E) i2c
 _smbus(E) thermal(E) battery(E) rfkill(E) ac(E)
Feb 10 12:35:20 valkyrie kernel:  amd_sfh(E) fan(E) button(E) tee(E) joydev=
(E) amd_pmc(E) loop(E) fuse(E) dm_mod(E) efi_pstore(E) dmi_sysfs(E) ip_tabl=
es(E) x_tables(E) ext4(E) mbcache(E) jbd2(E) amdgpu(E) amdxcp(E) ucsi_acpi(=
E) i2c_algo_bit(E) drm_ttm_helper(E) typec_ucsi(E) ttm(E) roles(E) drm_exec=
(E) drm_panel_backlight_quirks(E) typec(E) drm_suballoc_helper(E) xhci_pci(=
E) nvme(E) drm_buddy(E) drm_display_helper(E) nvme_core(E) cec(E) hid_multi=
touch(E) nvme_keyring(E) xhci_hcd(E) video(E) rc_core(E) amdxdna(E) hid_gen=
eric(E) nvme_auth(E) ghash_clmulni_intel(E) sp5100_tco(E) gpu_sched(E) usbc=
ore(E) ccp(E) crc16(E) hkdf(E) thunderbolt(E) wmi(E) i2c_hid_acpi(E) i2c_hi=
d(E) serio_raw(E) br_netfilter(E) bridge(E) stp(E) llc(E) nf_tables(E) msr(=
E) nfnetlink(E) efivarfs(E) aesni_intel(E)
Feb 10 12:35:20 valkyrie kernel: CR2: ffff8ec348b322d0
Feb 10 12:35:20 valkyrie kernel: ---[ end trace 0000000000000000 ]---
Feb 10 12:35:20 valkyrie kernel: RIP: 0010:sched_mm_cid_exit+0xdf/0x1f0
Feb 10 12:35:20 valkyrie kernel: Code: 48 03 05 8c e9 48 02 8b 08 81 e1 ff =
ff ff bf 89 08 8b 05 34 74 b7 01 83 c0 3f c1 e8 03 25 f8 ff ff 1f 48 8d 84 =
43 c0 06 00 00 <f0> 48 0f b3 08 48 81 fe ff ef ff ff 77 08 48 89 d7 e8 4b a=
7 cc 00
Feb 10 12:35:20 valkyrie kernel: RSP: 0018:ffffd4358bea3c08 EFLAGS: 0001000=
2
Feb 10 12:35:20 valkyrie kernel: RAX: ffff8ec344b322d0 RBX: ffff8ec344b31c0=
0 RCX: 0000000020000008
Feb 10 12:35:20 valkyrie kernel: RDX: ffff8ec344b31d10 RSI: ffff8ec344b31d0=
f RDI: 0000000000000007
Feb 10 12:35:20 valkyrie kernel: RBP: 0000000000000000 R08: 000000000000001=
0 R09: 0000000000000001
Feb 10 12:35:20 valkyrie kernel: R10: 0000000000000000 R11: 000000000000000=
0 R12: 0000000000000000
Feb 10 12:35:20 valkyrie kernel: R13: ffff8ec370e76300 R14: ffff8ec30c10000=
0 R15: 0000000000000000
Feb 10 12:35:20 valkyrie kernel: FS:  00007f7e95e956c0(0000) GS:ffff8ed2920=
88000(0000) knlGS:0000000000000000
Feb 10 12:35:20 valkyrie kernel: CS:  0010 DS: 0000 ES: 0000 CR0: 000000008=
0050033
Feb 10 12:35:20 valkyrie kernel: CR2: ffff8ec348b322d0 CR3: 0000000108f7b00=
0 CR4: 0000000000f50ef0
Feb 10 12:35:20 valkyrie kernel: PKRU: 55555554
Feb 10 12:35:20 valkyrie kernel: note: git[17173] exited with irqs disabled
Feb 10 12:35:20 valkyrie kernel: note: git[17173] exited with preempt_count=
 1
---- 8< ----

The stack decode showed the very same code path.

% scripts/faddr2line vmlinux 'sched_mm_cid_exit+0xdf'
sched_mm_cid_exit+0xdf/0x1f0:
arch_clear_bit at arch/x86/include/asm/bitops.h:79
(inlined by) clear_bit at include/asm-generic/bitops/instrumented-atomic.h:=
42
(inlined by) mm_drop_cid at kernel/sched/sched.h:3746
(inlined by) mm_drop_cid_on_cpu at kernel/sched/sched.h:3762
(inlined by) sched_mm_cid_exit at kernel/sched/core.c:10737

This happened only once, and can't be reproduced since then, though.
I must have been a very bad lock yesterday.


Takashi

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/8=
7fr77tvrz.wl-tiwai%40suse.de.
