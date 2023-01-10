Return-Path: <kasan-dev+bncBCYYJNMLYYMRBD7362OQMGQETIFSEGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3c.google.com (mail-yb1-xb3c.google.com [IPv6:2607:f8b0:4864:20::b3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 26FA3664C88
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Jan 2023 20:33:37 +0100 (CET)
Received: by mail-yb1-xb3c.google.com with SMTP id w9-20020a05690210c900b007b20e8d0c99sf13730142ybu.0
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Jan 2023 11:33:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673379216; cv=pass;
        d=google.com; s=arc-20160816;
        b=dDCzVn74NBFwqGxil8nmh3Q7xpPy0dazBr/wsvvVCWSRLpr5sqOOBO2jZ4QkX4Cshy
         nSOJhcCWihscpxOfDReUYrgWmxirB+aV74ukX1NXF6YrvYYuBoq/r5nuFAf83zIIgSZh
         /zhitWiWaSK2lgbYRy6kfkWX5knfgTIvqV2H137HSF3wW7ldgcc/hpEsWXsySIgPdXYJ
         Z2Ro1QisxzT+PWy4z/NuoRpTZtaI0Avf2al4Rq2ADykbgqASZgO7iI2yGHwhwz3yUXMW
         YZnVNKa2AW41OMwx+uZopwQZIXbVdbsz5Sfmd8ML6P/bPSSevltv9F2M5eaws1JSiq3S
         0bgA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=IzBcuNgQH6nNMf6N9g+3TApJXcdIAo6JKmZIGXPVc3s=;
        b=Vpx4i8LE/Igibxbhh+2yQBYg4PPWUXTaAiq2g7IxC/G1GoelVzPZS4UjhLtbebZv8B
         aBKt4AiTRzDZnJHBUSwbufJnQNC5I2Iq9pYa8RsUIwnHKXlEJ3H+RoX/l9NOQhjJs+OV
         5PFPHWYIjgdLJRwy9crBn1o1F+iQGjgBEbZzu/SArcKvSrpM+LTNxbY44MwHxxacl8B8
         lBKptFmA6pdXpV3f070grDcVdFVpUBPDCeR6R2TJFV0FeyVmoBLRoL+UEMeDy+roGYrp
         t/LPMoKAhjwZmju9VPJwI02I3bkfvTaxIhHDwjMDxPFIoODiMKmi1ANRIrZiRNO/YXlx
         OD+Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=fail header.i=@mit.edu header.s=outgoing header.b=Fv5SZWlB;
       spf=pass (google.com: domain of tytso@mit.edu designates 18.9.28.11 as permitted sender) smtp.mailfrom=tytso@mit.edu;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mit.edu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=IzBcuNgQH6nNMf6N9g+3TApJXcdIAo6JKmZIGXPVc3s=;
        b=jVHk7hziWTZKDhDzQNM+nme8CHcTDpRuy0AhGP5r/MgqFXcC0NGYUVj9EyFYrezrG9
         N12Qb9pNKwuCZ5cHTZI2/Ch5hTJfnT34D7K+AaEzcUyhH2l1h8Sql1KjDEaytJ6di3oS
         jUaXbig0A5INoeQDUktVxT7Ug5MDAtfByDLYWS+3gaa1Q7UG43ZzTCwuGPCzn7HNkI7V
         cg17AJbH8x3oKqOr0x2ZkVZm+nDrZ5KR5O6eAdLx+X0hoKsQl5q6V0fgcBTjZAH0o5+e
         AUYK7frtNGy8BhwpDHk7L0ycrxRgUD2BYKXl5CxwQwnHcqziVRSOZ5oZP7LJtgYTIjco
         n/8A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=IzBcuNgQH6nNMf6N9g+3TApJXcdIAo6JKmZIGXPVc3s=;
        b=SmKzeGG1LZOd98zAyh4dLSidAMHG8quqx4brvy1XGJFThax1kpGQwRLe8DqHHI+opK
         9GJm0adxeD3IbcuDNT/l2wuh2wcz9hPHpjS5eIwl05oi1GdOTuo02j4E1MJOWtvyAQNr
         W8PHz2+MdY/pE2teBnh6ivBHdGJZ8UvbyvJQ+fzM8m4YkDNROI6aL+Fv/K4l08wnzer+
         409BRlBW3ByivOpjj8VRuiJ69xdhmj/Rcg4DqvVc05Dagbr8RsqVF8CxldMiUT8zZS2b
         eBBeABP0nXccn4+6HeVMGZlGCIP/Ek0vjH3fj1UBEKxGk4jM57uuPCujp1+22OWw/43/
         ZFMQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2koFYP4S3DzF2qnQ4xJU3GnVNL+q3hqHV46uEO6Q5pY4CWqFoGbD
	BlNz96sCQINbLcKK1RY4Ssk=
X-Google-Smtp-Source: AMrXdXvQHQkkSTTDF7a+19wsKAdS5f7lq4LZV62dbsWqauCVXHN6/DXTmg1PTeZxbE+VwRZGlzun7Q==
X-Received: by 2002:a81:af0e:0:b0:478:1c89:6462 with SMTP id n14-20020a81af0e000000b004781c896462mr672669ywh.150.1673379215821;
        Tue, 10 Jan 2023 11:33:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:690c:289:b0:3fe:c52c:dd9a with SMTP id
 bf9-20020a05690c028900b003fec52cdd9als6418489ywb.4.-pod-prod-gmail; Tue, 10
 Jan 2023 11:33:35 -0800 (PST)
X-Received: by 2002:a81:7c54:0:b0:4c6:54a2:bf96 with SMTP id x81-20020a817c54000000b004c654a2bf96mr12901275ywc.22.1673379215252;
        Tue, 10 Jan 2023 11:33:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673379215; cv=none;
        d=google.com; s=arc-20160816;
        b=TNx2VcH0K1rb4tQSCbTMwDPANRW9pZC4Sn4t/1ARmGBh+Z9gWal7FSwkxL8KmJas9z
         o0ST9Uc52DOa9Bqw21SrAVWffao+YzQ3Jch2i3atvkEjecCRn1q6cMbPWh/VeRoha6Yh
         2v1y+5bqBxSB5cys/SJcN1srH6I219va8ZXbvBCduSTfqdjDBKARCJ2R/A3rA2ShgMxt
         NLxPNV/OPpUvrcNJOnYKwyEhwwrpnFhUAMpYLawg0197x6L7ywOwpOrx8lOY3fXweDng
         Nl8uwuNihsGnJB1c15wGCR2rDjhfZx8LmBwKznNwH9zstXQtKR85IWDCl03KBfZB7d1Z
         82CA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=yFMDQJkhnPi33MXjl8llO36UCmAmUNpTyoziClurNHw=;
        b=G4MtC6pTd+JeuuW2n4mpsWZZkuQhjoH3Xw0xqKRbqWz0Fh0FFDEBKJsSfOyQeG1en5
         HCgS69/rJJKJ0ca2Pkycx6n81AWOUPB5b4HFfBVMbEnUK1jENOZcVJ4JH5zQes2Di7IS
         Dd3RSM+h57hnxgRVhZkfJCg1zrcyBasCJgqdrwqc51e3huMoYn/HAh/rEzjsHVP/a5o/
         UQQa03DwYRA4RlEqgFIXxiUCEda+HqliYLVUZJb1Y0vqbv2AuFJ8NU/FV+hc7F62cjkW
         VkD8Ti/Q5W/6rC88HcoPuqn6ShMrda+DFvgsMczOaHl9FFk9w20nZGPNrfnHgeigBD/Y
         kWNw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=fail header.i=@mit.edu header.s=outgoing header.b=Fv5SZWlB;
       spf=pass (google.com: domain of tytso@mit.edu designates 18.9.28.11 as permitted sender) smtp.mailfrom=tytso@mit.edu;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mit.edu
Received: from outgoing.mit.edu (outgoing-auth-1.mit.edu. [18.9.28.11])
        by gmr-mx.google.com with ESMTPS id bp11-20020a05690c068b00b003f5fa41badbsi921110ywb.2.2023.01.10.11.33.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 10 Jan 2023 11:33:35 -0800 (PST)
Received-SPF: pass (google.com: domain of tytso@mit.edu designates 18.9.28.11 as permitted sender) client-ip=18.9.28.11;
Received: from letrec.thunk.org (host-67-21-23-146.mtnsat.com [67.21.23.146] (may be forged))
	(authenticated bits=0)
        (User authenticated as tytso@ATHENA.MIT.EDU)
	by outgoing.mit.edu (8.14.7/8.12.4) with ESMTP id 30AJX3eG002500
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 10 Jan 2023 14:33:16 -0500
Received: by letrec.thunk.org (Postfix, from userid 15806)
	id 383A18C06D5; Tue, 10 Jan 2023 14:33:00 -0500 (EST)
Date: Tue, 10 Jan 2023 14:33:00 -0500
From: "Theodore Ts'o" <tytso@mit.edu>
To: Robert Dinse <nanook@eskimo.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, bugzilla-daemon@kernel.org,
        Andrey Ryabinin <ryabinin.a.a@gmail.com>,
        Alexander Potapenko <glider@google.com>,
        Andrey Konovalov <andreyknvl@gmail.com>,
        Dmitry Vyukov <dvyukov@google.com>,
        Vincenzo Frascino <vincenzo.frascino@arm.com>,
        kasan-dev@googlegroups.com, linux-mm@kvack.org
Subject: Re: [Bug 216905] New: Kernel won't compile with KASAN
Message-ID: <Y729bEXOkwfGBsZE@mit.edu>
References: <bug-216905-27@https.bugzilla.kernel.org/>
 <20230109160929.1ecacff5fb8ca2b1ae25141f@linux-foundation.org>
 <9acae081-9d4d-3dd5-8b2c-52c72592e81c@eskimo.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <9acae081-9d4d-3dd5-8b2c-52c72592e81c@eskimo.com>
X-Original-Sender: tytso@mit.edu
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=fail
 header.i=@mit.edu header.s=outgoing header.b=Fv5SZWlB;       spf=pass
 (google.com: domain of tytso@mit.edu designates 18.9.28.11 as permitted
 sender) smtp.mailfrom=tytso@mit.edu;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=mit.edu
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

On Mon, Jan 09, 2023 at 08:58:41PM -0800, Robert Dinse wrote:
>=20
>  Increasing to 2048 did allow kernels to compile with KASAN enabled. I
> am curious why e-mail only? It would seem bugzilla, a public forum would
> make this fix available to others who may be experiencing the same or
> related problems.

Not all kernel developers pay attention to bugzilla.  (In fact, most
kernel developers do not.)

>=C2=A0 Interestingly, I could not locate the symbol with
> xconfig, had to hand edit the .config file in deference to the fact that =
it
> tells you not to.

If you search for FRAME_WARN in menuconfig ('/', followed by
"FRAME_WARN", followed by return), it will report:

Symbol: FRAME_WARN [=3D2048]
 Type  : integer
 Range : [0 8192]
 Defined at lib/Kconfig.debug:395
   Prompt: Warn for stack frames larger than
   Locationf
     -> Kernel hacking
       -> Compile-time checks and compiler options
 (1)     -> Warn for stack frames larger than (FRAME_WARN [=3D2048])


That being said, you can edit the .config file if you know what you
are doing.  But if it breaks, you get to keep both pieces, since there
aren't the safety checks and guardrails of the supported paths.  For
novices, I recommend saving a copy of .config before editing the
.config, and then afterwards, run "make oldconfig", and then diff the
resulting .config with the saved copy to make sure there aren't any
unexpected changes.

Cheers,

							- Ted

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/Y729bEXOkwfGBsZE%40mit.edu.
