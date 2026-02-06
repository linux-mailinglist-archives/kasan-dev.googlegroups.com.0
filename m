Return-Path: <kasan-dev+bncBAABBJ4XTHGAMGQEL33QIXQ@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id wgg0E6lLhmndLgQAu9opvQ
	(envelope-from <kasan-dev+bncBAABBJ4XTHGAMGQEL33QIXQ@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Fri, 06 Feb 2026 21:14:33 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id D95C81030CF
	for <lists+kasan-dev@lfdr.de>; Fri, 06 Feb 2026 21:14:32 +0100 (CET)
Received: by mail-wr1-x43a.google.com with SMTP id ffacd0b85a97d-4362f8b5a65sf550117f8f.0
        for <lists+kasan-dev@lfdr.de>; Fri, 06 Feb 2026 12:14:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1770408872; cv=pass;
        d=google.com; s=arc-20240605;
        b=UWWAolsbUfwCIb6uWkN6mCNPgVTM2VdawHMwwCYljaQAYjMoq1xcjO13kgBTNp87C2
         w9ZjVW49ZEWbE+jZ+WI3DZFNjmTKUBSHb3iiz/bOxola0p3btILZ+I3RwpwWItAJix4K
         N5CxVX/MEiF1FNVEDPJE0FrwgL7SOgb8yomdh58BX2yWBAXsgnJm687N8G+SXF2jAH6s
         fEsGlxtn11RhrixGcP85al22BoD9R0OXYsvVo8J2iNfsBO5Vu+ATBlKnsyv5AEyBaFIm
         x+nTb5pXOjwPftSEsQ1t3ry5/l6S5Dx5doyHkXJy6AyCVyno6tb2R2WOU/kdq1i4z7XI
         o/xg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :mime-version:feedback-id:references:in-reply-to:message-id:subject
         :cc:from:to:date:dkim-signature;
        bh=omkXGNiHble2DHt9ytKaWTWXrYHHwndRELsL/bz6VFw=;
        fh=B+twWFpN5DvCgJenV7976/qKuem2OY0pW+5yRnBty2E=;
        b=CYvtowJne9KQBOKkRTwfO8pb0jrhryhRRqNtoywaBADdvFhyB/PuhPBPh1iCQvQkXm
         VCkwXKS+elSf42spfIMkl3VSh6AnuvKo4x11rGIw0ylHU7ol+SqDAYCZmCRdkVirjT6O
         QtZtHMgBr6qE+66TBtyk32/6puG+6BQj/WSSv9ABcmB18+UBaEb+VjDsw86dnvFVg7oH
         hKSE63mXQ57iJvpntNw94gTnOv27jTMmqIAKmEMVtZaOmcqiTkilRIFp5FhFI7vqDqHD
         QE14FOB+gCHn3yQ22H+Vz/u+18YoRKVAQjMULgOk99l35W1uRwqoHgz3X3nV83R3NCu5
         6o4w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=U3OzgVFZ;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.31 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1770408872; x=1771013672; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=omkXGNiHble2DHt9ytKaWTWXrYHHwndRELsL/bz6VFw=;
        b=R/Ip+ALCXKrUgC3ajdAQ2FziPLgDig9h1P6KPIf1zEJe9eHBRAwwkOgRsbdWIAGDft
         OGopsAY4J6Znmaq9x7stjQOeDgpI8uGSb7NomifIJXqXjlC+DpcJWolGxFlA525AN+K7
         lctJUXBXUU7XlM19f7cE6sjDMXeE8x5jNutFva+aMMa7s0EkPEyxgqrSmjF1BkxwBnLw
         PyBDNod+yo8AYo2RiJzio0iILwVjyQ97wNQc+UzPX9I9vI8pwq9N+7s1ffBQwu0S/pRl
         zkMyLC5u5ClGfo83Brmp+ti+QPzEM2ieVDAxQoHIIVesx9pmyOQNT3jv5Bbr4YyvwbvD
         5g5Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1770408872; x=1771013672;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=omkXGNiHble2DHt9ytKaWTWXrYHHwndRELsL/bz6VFw=;
        b=MtvGxyubKq1e6LOgjWQa89y7YkR85uol7y6VpTdjilo8t7mgml3P11k3PzpMPob6G3
         iBCkn2zu26S7Sof3YTidv+EzAJOe+8ExrXN+UccZBw/9byxeTRxsXVrX3jFSLx26yzfz
         LNaT8lYqjdQVV9IXukktTNJwG1fGm0nig4/qNnWbtl9AXEPOPOxVt15kSt1y0aS81WDD
         pyM1PAMU+1l2NHlHBI784Q6vUgvGJzUotgFcbKGNvye+e2RnD2ZmkA/HDmmg3YhE5qnr
         WziZmyN/Ln1N5CJX10i/Bg7ok5FeW+56NbFn+6Hr2VH6QZlX5vVJ/si5rPijlhWqGFkj
         5mKg==
X-Forwarded-Encrypted: i=2; AJvYcCXDXNLRdWgrRbo66mXUcAIm4jiHpuK3ciZ3zDDj6S3c7FM4s7iw88EmKXz0odS0eCjCu0D77A==@lfdr.de
X-Gm-Message-State: AOJu0Yz6U+E+ehxxpK6AtASOJkZmAEM0C3bwm19PDreKXvsfewgWBlmI
	wWtXzTM4k6JhUh4H3A3i0PMtLBUEXk8rY7F0Y4ZYqRPavAuxcKrAvhIM
X-Received: by 2002:a7b:c3d5:0:b0:47e:e38b:a83 with SMTP id 5b1f17b1804b1-483178ebf8emr69861565e9.7.1770408871775;
        Fri, 06 Feb 2026 12:14:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+E8yG+/kyC3fLmaVXGVWlYPVNMnVk8rZNgG1+c/0CggfA=="
Received: by 2002:a05:600c:524e:b0:477:9e7d:40a2 with SMTP id
 5b1f17b1804b1-4831752ddb6ls14293495e9.0.-pod-prod-00-eu; Fri, 06 Feb 2026
 12:14:30 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXLprE1zXkiYW/RC3TfE4ypx2tPLkv8OvANmvYflPFYxOpgSEDmDiZ0u2UDxSf5PtMUb8EtrWa320M=@googlegroups.com
X-Received: by 2002:a05:600c:3588:b0:481:a662:b3f3 with SMTP id 5b1f17b1804b1-483203ab7b0mr65610785e9.7.1770408869993;
        Fri, 06 Feb 2026 12:14:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1770408869; cv=none;
        d=google.com; s=arc-20240605;
        b=ehbsLcSJbBW3KMcqqw+m6wHxoeg9vYAjlHhixWufc7R6H6cFSZgILkv18RO5Yl+NQw
         bTapqcujINRKFegEscmN5bXYkVxtJBHYLThlaazlNLSsTHVQPw/3i82mu7fu9xZEprEu
         5cKV47aFczeZiXdOvZbS6acmyiAscVkYcW8+GiLM2A1EWW6OEtYK2dUt3xMMkWe0XYu8
         wYGdpNDrE+Qb/6VoP6gdlyg/80+LzAJEW08xffJl7aRFcOE9kfJha8Jqcvypfpk3qag7
         flHBrekoY3BSf8amkLa7UerFf0Zka8s+z0ptf/owJ2ryypkYCbSJlgCIehxWzmDmIOTK
         v/wQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=+2kf5hPOrCDamoohAxbiRlLxvzqHhWFTaCpLlhR4Cz4=;
        fh=eaE7/DcB8dtsl6A0v4xvEVQ8EO2SRp5htyvaLuDtZ/I=;
        b=dTFcCUYqlClGf/mYT6bRFZmRAVf6BFEQj2v6l0vN3rmniqGZH7TcfQlkaC56b+uyns
         QfCdKBsZwVSoV68QlD9hYjFXl42ITqQKyrf030+uhv7b3Rlg42BHLfxrkP1mhi0Lv9qW
         MZPiW6up93jbdnjncVxNJeP6pw49uSCg72T2LSJNEaQGoQtOi+Z4wPHu8xH2ZY6oWvhJ
         HEenErbWlaa+mk03f+QvZJpebIwF3xPB2IcfxY2upGpygDguF1LVwqlVPi2RD5FTW9hX
         wgu7Igc9EfEIGDw/WM9ptIq6MsMaRU4vUC4ZAneBSlpKuIBiarZNnMXoSlN8jQVMlKyo
         ueIw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=U3OzgVFZ;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.31 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-10631.protonmail.ch (mail-10631.protonmail.ch. [79.135.106.31])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4832039713bsi417225e9.0.2026.02.06.12.14.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 06 Feb 2026 12:14:29 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.31 as permitted sender) client-ip=79.135.106.31;
Date: Fri, 06 Feb 2026 20:14:25 +0000
To: =?utf-8?Q?Maciej_=C5=BBenczykowski?= <maze@google.com>
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Kees Cook <kees@kernel.org>, joonki.min@samsung-slsi.corp-partner.google.com, Andrew Morton <akpm@google.com>, Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, Marco Elver <elver@google.com>, Andrew Morton <akpm@linux-foundation.org>, Uladzislau Rezki <urezki@gmail.com>, Danilo Krummrich <dakr@kernel.org>, jiayuan.chen@linux.dev, syzbot+997752115a851cb0cf36@syzkaller.appspotmail.com, Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, kasan-dev@googlegroups.com, Kernel hackers <linux-kernel@vger.kernel.org>, linux-mm@kvack.org
Subject: Re: KASAN vs realloc
Message-ID: <aYZJ2Ohug6b9Vth0@wieczorr-mobl1.localdomain>
In-Reply-To: <CANP3RGeHnhufYyc0P2OiKJbXdZjPW41TP=JS6nYk9xGRU8UuKQ@mail.gmail.com>
References: <CANP3RGeuRW53vukDy7WDO3FiVgu34-xVJYkfpm08oLO3odYFrA@mail.gmail.com> <202601071226.8DF7C63@keescook> <btracv3snpi6l4b5upqvag6qz3j4d2k7l7qgzj665ft5m7bn22@m3y73eir2tnt> <CANP3RGfLXptZp6widUEyvVzicAB=dwcSx3k7MLtQozhO0NuxZw@mail.gmail.com> <CANP3RGeaEQipgRvk2FedpN54Rrq=fKdLs3PN4_+DThpeqQmTXA@mail.gmail.com> <CANP3RGcNFgLSgKYPjmro2s1Es04Pnhf+4wHpnSwRX4M8bLDW9g@mail.gmail.com> <aWFKEDwwihxGIbQA@wieczorr-mobl1.localdomain> <CANP3RGeWLMQEMnC03pUr8=1+e27vma1ggiWGWcpX+PcZ=SsxUg@mail.gmail.com> <CANP3RGeHnhufYyc0P2OiKJbXdZjPW41TP=JS6nYk9xGRU8UuKQ@mail.gmail.com>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: bd556a4a64f26ab613af6dbc5d550912c9ffd249
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=U3OzgVFZ;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.31 as
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
	TAGGED_FROM(0.00)[bncBAABBJ4XTHGAMGQEL33QIXQ];
	FROM_HAS_DN(0.00)[];
	MIME_TRACE(0.00)[0:+];
	RCVD_COUNT_THREE(0.00)[3];
	TO_DN_SOME(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[19];
	FREEMAIL_CC(0.00)[gmail.com,kernel.org,samsung-slsi.corp-partner.google.com,google.com,arm.com,linux-foundation.org,linux.dev,syzkaller.appspotmail.com,intel.com,googlegroups.com,vger.kernel.org,kvack.org];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	HAS_REPLYTO(0.00)[m.wieczorretman@pm.me];
	TAGGED_RCPT(0.00)[kasan-dev,997752115a851cb0cf36];
	NEURAL_HAM(-0.00)[-1.000];
	FROM_EQ_ENVFROM(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	MISSING_XM_UA(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	DBL_BLOCKED_OPENRESOLVER(0.00)[pm.me:replyto,wieczorr-mobl1.localdomain:mid,mail-wr1-x43a.google.com:helo,mail-wr1-x43a.google.com:rdns]
X-Rspamd-Queue-Id: D95C81030CF
X-Rspamd-Action: no action

From what I see kasan_poison_last_granule() is called through:

__kasan_vrealloc()
--> __kasan_unpoison_vmalloc()
----> kasan_unpoison()
------> kasan_poison_last_granule()

and the arguments are "addr + old_size" and "new_size - old_size" so it loo=
ks
okay I think.

On 2026-02-06 at 11:07:12 -0800, Maciej =C5=BBenczykowski wrote:
>While looking at:
>  https://android-review.git.corp.google.com/c/kernel/common/+/3939998
>  UPSTREAM: mm/kasan: fix KASAN poisoning in vrealloc()
>
>I noticed a lack of symmetry - I'm not sure if it's a problem or not...
>but I'd have expected kasan_poison_last_granule() to be called
>regardless of whether the size shrunk or increased.
>
>It is of course possible this is handled automatically by
>__kasan_unpoison_vmalloc() - I haven't traced that deep,
>in general these functions seem to have a terrible api surface full of
>razors... with hidden assumptions about what is and is not granule
>aligned.

--=20
Kind regards
Maciej Wiecz=C3=B3r-Retman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
YZJ2Ohug6b9Vth0%40wieczorr-mobl1.localdomain.
