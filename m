Return-Path: <kasan-dev+bncBCCMH5WKTMGRB4WYZ3FQMGQETTFUCFA@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id uFs6AnWsc2nOxwAAu9opvQ
	(envelope-from <kasan-dev+bncBCCMH5WKTMGRB4WYZ3FQMGQETTFUCFA@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 18:14:29 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-dy1-x133e.google.com (mail-dy1-x133e.google.com [IPv6:2607:f8b0:4864:20::133e])
	by mail.lfdr.de (Postfix) with ESMTPS id 9E75978DB6
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 18:14:28 +0100 (CET)
Received: by mail-dy1-x133e.google.com with SMTP id 5a478bee46e88-2b6b9c1249fsf4318748eec.1
        for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 09:14:28 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1769188466; cv=pass;
        d=google.com; s=arc-20240605;
        b=jfRGVSZZNm5u9oNb8XxsCzPS32PnI/KzU+l77TPV7zrCyPK7Fc8ufzuyUxGoK4ee5L
         FE67ndTH4LOvPE0rK/WogYTKPXLV/5Oe8KqIVlIuaWDTh690Y+fSclvW50TSYSaAxuEa
         6kbVy3/Y74p24Qghx7Zepn/8V8lOSF9bIiEpvSKU1BiMyhosks8NNF2broilW3sehROe
         AOwaVGaw5eRna0Ib8TyJsjdpikOvq30k/e6FtWc2rVk61fmPmO2+WBDSwJVkzo7bVy1i
         Uot2h4VKyTswhetjFBIA3FScXcG27ofu1VBgnC48+jq213ZHTw79SH7GB+vral3tTwMT
         yZuQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=AjUZoKOmlyX5viLZCqrkL2tiiMYFIUTAdxrAXNIVQCg=;
        fh=uXKQum4d9RJVgFWjQFr6zEZT3ngzIxMXQ+2p9kGDsUY=;
        b=CpVwgco9eNuZa/SPfslwf0EIt7uFvJHr71zO07rrP9Gm9NfhP50MUHOQ4ikpUpqytc
         DWxtzHnVaz/FILV56mctYZRK/dBay1anGjeDY0lsEAi3x5yyOXFQ5jpuB3k1XNV6kXTA
         je5C7rAnZj/KbVeZWv7mOoLy8bVupvTHhihHvJgosj9u4oRaIDrKQkveLu3g2tc51ZkQ
         Np9+hcWDNAy9CzYomfc8AUhU1dPNXIUBWgrhiRapU1LqpwnddQEnx5TUwAgM0VvrauEW
         VJtKe8J1FVSbISYx9P5KbFLNtb2+j1BEFhHOWKYif7EATh/S0CEtN82FmXhj1miLkXN9
         s0hw==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=oPdwLz1K;
       arc=pass (i=1);
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::531 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769188466; x=1769793266; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=AjUZoKOmlyX5viLZCqrkL2tiiMYFIUTAdxrAXNIVQCg=;
        b=M3UAVxP0932/fm1zL6oGb/AmAlvQOw2TranvQqfAV4KEdQq5dbZQkIJTIABxE7L61j
         eKOTSSPG6w3wF/7m8wKm7LsQZNhOE6guWQRpxm3hlI7MGWAEwFSy/jBXLO2ZXrKq1t4k
         ZkQDR2MbaBec1PBSru+9LS+8GiT7QEVvkiZcNA6TUhqdU8hzNHhfw4aUCXikDvl9FkfX
         yzHyflbS7SdhkffiWKxyItp5DFoR/xjiVrwy4jY9NRqzZK4yDMK5H7snOqWsPLuEW4ic
         rJS7HwRICJLRXpQ2niGhWwYVlkK9PPEa5dst26o9lrwsRcV3zKqKgkBUmX4rUdGNo4vR
         WiXw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769188466; x=1769793266;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=AjUZoKOmlyX5viLZCqrkL2tiiMYFIUTAdxrAXNIVQCg=;
        b=AQd0kM7xhY7XyWfDMt+vkO3F34HUQ/GWiFkNxHvyWojJrmk344CjfnOLBhTc0NLeW6
         H9Cd5kL7fem9lmdsSi+0uZTNtElqVywoXBOCI5JeqvOL5/9e3OBgzuJjc/5SDCI1/AsU
         PJahExzPcaN5ySslhyigCVDwwxpF86OO52TP1ycFRSG8YzvEkQi+QD5TWAbiImdezo89
         gOGtGR2jvO0mYIoaV25tQTsYj+lACftKJwMxZ+JRjjR3dfmRQ7bK4og/mpW6Bfi0bpiH
         8RBDqrN6ig4FMMwAhyHmpSBBP8pRFstho10r1RM1ALtZiiNHgfl2wJxDbkQqLFFNoVzO
         W5Kg==
X-Forwarded-Encrypted: i=3; AJvYcCX4iwL2PcbPPvHcnOqLb6SmsJfYEO4icRrgrnQGcawf3/wjC6vat6A4XFeY51fF5CILacNxHA==@lfdr.de
X-Gm-Message-State: AOJu0Yy3J8suuEbo8mtRI+Hqr+R9jWHm6FDW2L8XaJnrvbWyUEBuYHIB
	750JK/K9v8aAoFIX86ge+ySqw5dsRs6aytCTboa6V6ADGuXQUGUpAZWh
X-Received: by 2002:a05:7022:2394:b0:11a:44d1:533a with SMTP id a92af1059eb24-1247dbb93a3mr1760564c88.12.1769188466438;
        Fri, 23 Jan 2026 09:14:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FuotRqybfJXvplnPB4uPAtAOrZzckAgggM2bsWKi78PA=="
Received: by 2002:a05:701b:2088:20b0:11b:50a:6264 with SMTP id
 a92af1059eb24-12476be3eb0ls1093819c88.0.-pod-prod-06-us; Fri, 23 Jan 2026
 09:14:25 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCWFVIeO1RSkbablTAsQCPT8+NMijs/tsmyYWP9NnWtWp4c45oqT2r+JsCILyWgkk2txmnnLlAXKeEw=@googlegroups.com
X-Received: by 2002:a05:7300:214d:b0:2b7:1008:9f51 with SMTP id 5a478bee46e88-2b73995a5cdmr1385465eec.8.1769188464959;
        Fri, 23 Jan 2026 09:14:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769188464; cv=pass;
        d=google.com; s=arc-20240605;
        b=iw9yvsr4VEN5VA9mcdfkxCwNcd2OE1SJGU4EdjV1r2UbRm8j2nqSdCwDcMHKXleox/
         LuRmMGHhhPQFSYlI8TBZz2a0PopwKoozRCuvv9TWIlafXAYgtECVR8VmqIOH6wPWu4T0
         Lz4fT7FMRtIlfUo3mVxYxxVmVtmuzhW1u6kqwxvuZjrnRyVisfd/TseuC6zWNQI2q75J
         l+4u2Nen0DkJI6KIAdOXDb2SMqSivzDavhUuza/OAjv2Nt6JskMpK0bur75fstRrrVTd
         t6SHsR+Et3tCpGPxEETcccvTNPk4IMTKNH9MGXEPB651mvvb3LoWpIgGrvcfwrvEKfo+
         60GA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Pyus2eAL7FKDQhWIyVygHBSccAuw4WPN19E7Fh2kf3Y=;
        fh=oAOtANvjGjq1UlqktIa6PJlYkI3+hwX7g6wubbD/b/4=;
        b=EPtH77p0uxqHPedLQqt707nhCxXxuW2zmR+QpGhkcN8jbKIq4QMNbjP2FOZkqWyys/
         BdVnfUenuIx8D8gEAn+V4Wq6PcpFRT8u4uPO+rC8zBDoet1Qi1ivBG+Tn8doAQQFBnln
         R4zPE9MmkKd5r4ORUmkAE+uhgKaxSZFZfvCC+VacLg1d0e2bNRHHChZacIzxziSmLiMN
         6w5RUQTo3yw3wwMmdUVzBionnPK6r94OgbopQyKQXPHWY2T82Rgdks1DqE0GdU89GWEi
         zJvq36T4j1RGKTOCwjjIig7cSSdWiCjYGR/RuTEtbg4/xWJjnoFY9HUNRIl+tL/1g4CB
         KvZw==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=oPdwLz1K;
       arc=pass (i=1);
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::531 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x531.google.com (mail-pg1-x531.google.com. [2607:f8b0:4864:20::531])
        by gmr-mx.google.com with ESMTPS id 5a478bee46e88-2b73a4c7245si99530eec.1.2026.01.23.09.14.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 23 Jan 2026 09:14:24 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::531 as permitted sender) client-ip=2607:f8b0:4864:20::531;
Received: by mail-pg1-x531.google.com with SMTP id 41be03b00d2f7-c2a9a9b43b1so1520413a12.2
        for <kasan-dev@googlegroups.com>; Fri, 23 Jan 2026 09:14:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769188464; cv=none;
        d=google.com; s=arc-20240605;
        b=SS90VZA7oKfn7petRNBm1YRURYp2HgrklAy1G048PtjPBqUbw+pHHa57DFqTp8dtbK
         Rw/jx3IoKw2YPdoQsV2h3GR/CEljww07IvOkkmMGZ9IyDqNtMKP0G++v9gej6d/2xvd9
         G1aslHMuFfqQu9hF4+nt31yIWHmtJtWBWQBYV5PPqHsAL3UmEhsaCADyY8r/129xqcoG
         u87y10lL5/Q+ig3GW59GDSil1rmbG5Ejc/+tXQeeBrGSHg9E7U5mG5dj5Cq4ubXeCPGA
         w8brvmSYtcdXF2jWarUIrRNywGBA+JB6QFV+3Zp3nJR7l2pKgqOqq/YzS5raoNadViHn
         Qurw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Pyus2eAL7FKDQhWIyVygHBSccAuw4WPN19E7Fh2kf3Y=;
        fh=oAOtANvjGjq1UlqktIa6PJlYkI3+hwX7g6wubbD/b/4=;
        b=HqY6Vg9ZaNli9hPOdjhxEnvx/XJg10K4WH43DbyHIviSeq3hb78lZIUeRr/Wk9FTdB
         AWX/mTs2efAMKId3aNiKCofrVW8mKwnrHXBkjAr2V7m7uQo7wdEB1a7Mc1pmBv1HZR37
         CeyvaiQKJpGD19Widv7suUmKUw4eVScR9iYqvQovRvy2nGkJA1tbrkoR5MsuxPpOeE7+
         EwO9HvmmYO8CWEj9e/oQmDmjll/HAUVOTaleUuKoDFFVvEcCuAMyk4as7jwqjSabahWy
         NbOSEupUyvIDZUzeo9NqFW7Ohlcxuwuc4RnDJJcgsbjegHS1BM6rM7mBz3AxNPoPMGTr
         enzw==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCWarSv9iSmAyYTYjBRWBZ5n31IsC+IERrf1tGUHc+ZebLs1tSToeJqxEJH30PJLl24mZs0loStywh4=@googlegroups.com
X-Gm-Gg: AZuq6aKCgFexGym37QQ2jku4gHXcQOoNEHNFLTr3lxOFntd96lvrUNPtgwI2DjD/6Ip
	ja6AISBRXl2SKAqc1WHK+avt/qzyQZIYYIny+25FlprgyIyquH9UgtY5WuVvOU5shBslEkYf6QT
	ouuw1Nayo/GKQ0UlR2jcHZwWrXG3Zu8JkrVhub9b8FPr+SZBOqhaVvwCkHKwzeFQEC48ldvPBvG
	PgBnRQNGpG0Ll6BDtRy7IXfqib3JPYIXn9D7KUm847gSp7IZG+aU2q9RWFdn6g7IkC62ogLUNw6
	X8b643Gm8zL9b5FeTtzCCve6qw==
X-Received: by 2002:a17:90b:1348:b0:341:8ac7:39b7 with SMTP id
 98e67ed59e1d1-35368b4001dmr2872028a91.25.1769188463940; Fri, 23 Jan 2026
 09:14:23 -0800 (PST)
MIME-Version: 1.0
References: <20260120161510.3289089-1-pimyn@google.com>
In-Reply-To: <20260120161510.3289089-1-pimyn@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 23 Jan 2026 18:13:42 +0100
X-Gm-Features: AZwV_Qh6jled3JZeU3ngx8ww-lKGy8zUdUXhvPlVWuqudohIm--Rh3iTGeTZBa8
Message-ID: <CAG_fn=WTEM5m7zcVO+S74JNz2t3nYY0vJNDyRrAhuHxrvHCv9Q@mail.gmail.com>
Subject: Re: [PATCH] mm/kfence: randomize the freelist on initialization
To: Pimyn Girgis <pimyn@google.com>
Cc: akpm@linux-foundation.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, elver@google.com, dvyukov@google.com, 
	kasan-dev@googlegroups.com, stable@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=oPdwLz1K;       arc=pass
 (i=1);       spf=pass (google.com: domain of glider@google.com designates
 2607:f8b0:4864:20::531 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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
X-Spamd-Result: default: False [-2.21 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=3];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	TAGGED_FROM(0.00)[bncBCCMH5WKTMGRB4WYZ3FQMGQETTFUCFA];
	REPLYTO_DOM_EQ_TO_DOM(0.00)[];
	RCVD_COUNT_THREE(0.00)[4];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	TO_DN_SOME(0.00)[];
	MIME_TRACE(0.00)[0:+];
	FROM_HAS_DN(0.00)[];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	HAS_REPLYTO(0.00)[glider@google.com];
	NEURAL_HAM(-0.00)[-0.993];
	FROM_EQ_ENVFROM(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	RCPT_COUNT_SEVEN(0.00)[8];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	TAGGED_RCPT(0.00)[kasan-dev];
	MISSING_XM_UA(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,mail.gmail.com:mid]
X-Rspamd-Queue-Id: 9E75978DB6
X-Rspamd-Action: no action

On Tue, Jan 20, 2026 at 5:16=E2=80=AFPM Pimyn Girgis <pimyn@google.com> wro=
te:
>
> Randomize the KFENCE freelist during pool initialization to make allocati=
on
> patterns less predictable. This is achieved by shuffling the order in whi=
ch
> metadata objects are added to the freelist using get_random_u32_below().
>
> Additionally, ensure the error path correctly calculates the address rang=
e
> to be reset if initialization fails, as the address increment logic has
> been moved to a separate loop.
>
> Cc: stable@vger.kernel.org
> Fixes: 0ce20dd84089 ("mm: add Kernel Electric-Fence infrastructure")
> Signed-off-by: Pimyn Girgis <pimyn@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DWTEM5m7zcVO%2BS74JNz2t3nYY0vJNDyRrAhuHxrvHCv9Q%40mail.gmail.com.
