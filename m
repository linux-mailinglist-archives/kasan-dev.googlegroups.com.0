Return-Path: <kasan-dev+bncBDB3VRMVXIPRBTET26OAMGQE5QOKEPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 77022649424
	for <lists+kasan-dev@lfdr.de>; Sun, 11 Dec 2022 13:15:09 +0100 (CET)
Received: by mail-wm1-x337.google.com with SMTP id n8-20020a05600c294800b003d1cc68889dsf960876wmd.7
        for <lists+kasan-dev@lfdr.de>; Sun, 11 Dec 2022 04:15:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1670760909; cv=pass;
        d=google.com; s=arc-20160816;
        b=v1NP7fJiayJBeQRCAyPm3ogrRQ6OQTL4TZB+PYqGjQ/1rlOxX8NJqFoHpridiZPOJg
         RNzA2iXbRdf0MNsUrgJDv+RM36fR38ySiro8LltaM9HdGpA3rleofpAChusk1lBSnbyE
         2iRKXtWD4R8isOBgg36kDtUMdzBFW3dnG97JMY0WlqCvWQU4kx0cfAD5mZCpaamkEMFi
         fHmzUG0L4TdUZtnmq6dlbo0q+eUlvbKgM5DC7ZU91Qlvhj4nm8gZjD4mE1Wci7g5VI5l
         /CFyqPLy1FZCvqMXmn201E7ZByBha5jobsQGXAvUK7XnjBGdlPAWPXS2WhT3SN2UoiRV
         pBkA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:subject:from:cc:to
         :content-language:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=Gw4HWEZX+flXtgVJpBy3dSKR+7lT9p3ZHhVjUn5fl/4=;
        b=Rc6Vz11IW+jM9Zf3S78Yy5ya8zPrwqXpv0wp1NSM6hKx5yhSRmgPFnmL8A5c26uu97
         Bb1EvPSu7ymQ1p7xHF2IcGgst4kRN+J5wCLY/K/5yYW1SL3LrNGikWL4GAicqYLFa2E4
         y50+ARmBgX6zUDppxExdkln1I2A4T7zadn2X+6c1cTzOUt/HLi9nfgcFp7KbxiUEZaHO
         n1G0GhXrHnK/cWq+WpBZE+vuU5LLCo+Dh2rO6wnrrw1joKgLmJyVTkPeC5i3ckiLvMrg
         ycsQq1qBtuA9FB0qFzPdSQQbswPNGay1qqgHi6MbxQiGOI68xHb1f39Ak37hwmLKUgig
         rgCg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=YK7Hyy+5;
       spf=pass (google.com: domain of jgross@suse.com designates 195.135.220.28 as permitted sender) smtp.mailfrom=jgross@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:subject:from:cc
         :to:content-language:user-agent:mime-version:date:message-id:from:to
         :cc:subject:date:message-id:reply-to;
        bh=Gw4HWEZX+flXtgVJpBy3dSKR+7lT9p3ZHhVjUn5fl/4=;
        b=sOdv0ncGPrXRrSSbm+Eo/FISrPwrVbgQ+KQwBOv5dD2h3JMhx8TOjTHozkNzCyo7S2
         qeoPlW0joPN1P5MzVKnl1u1j6P0BRuTREhbNeELTBh0d88AIhYsUgYUVqTCenf+BK1+4
         3D46t41B2dqNInFvDD7lE25K5ukyh9mEa+xt5Y+CVyo9Rggk6xhcUpci7yUzWfk57vJ6
         Eg1Ervb7XJAOYV9tTJA7KC0pL0boqVD6pRbBZU2F7r2fA1eLtz8Vdrp8gRotzMN07eP5
         U3Y/bVM7HOqLKkFEBK+E85Iz8GBglRLCOWBVUFMMew0ZYRddLWN7t1E3ESQHyQd+pU2E
         HDGw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:subject:from:cc
         :to:content-language:user-agent:mime-version:date:message-id
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=Gw4HWEZX+flXtgVJpBy3dSKR+7lT9p3ZHhVjUn5fl/4=;
        b=s8e6ttWpw7ed7A7KCavYdjOAuL/Kl2E1PjSHrdowBfL65/gSFyqlQgfRbz+NMuWQNP
         TQ1Ai1q4Mk9sb3eaA/xgvM7uvfCq0Mx6ZHl2l156RUjLixbSTyAkUf28k+o9UleHZrb7
         6U8MRyn8oVzXnsnZNlvk8hXMtuM3iEv4zTBwF8YOvXXm/TuAvIYSTy6zoS2Edx+0eSOT
         lASYskj4s2SqK4Cs90dA/PNFUCjfknLO8RmJvRA0p+tYxIOCgQ3xwTeeHOvmSsFRTa2H
         43/DrFct+i3UIYtnAFeLvGLlg/92NmjMXElrFwmE9+IU5kLV/fS5jX94x+WE/GH06icU
         l+uA==
X-Gm-Message-State: ANoB5pmrdYn4vocY5Pout47XWpZ6jB/aTQBhPhRbzCjiYQtv5x7/XnDk
	/0Vc2249cSO/rtJ8h/7jNjQ=
X-Google-Smtp-Source: AA0mqf41UsGnIiWRAuwOzvv0mfaXDJKD+kkQV77tYoIxh+8M1XRIPToqOSSz8p1rme4+omjdO0HHrQ==
X-Received: by 2002:a05:6000:1d8b:b0:242:750a:5b56 with SMTP id bk11-20020a0560001d8b00b00242750a5b56mr7342771wrb.271.1670760908908;
        Sun, 11 Dec 2022 04:15:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c444:0:b0:3cd:d7d0:14b6 with SMTP id l4-20020a7bc444000000b003cdd7d014b6ls7522657wmi.1.-pod-control-gmail;
 Sun, 11 Dec 2022 04:15:07 -0800 (PST)
X-Received: by 2002:a05:600c:1d09:b0:3cf:a39f:eb31 with SMTP id l9-20020a05600c1d0900b003cfa39feb31mr9503390wms.33.1670760907572;
        Sun, 11 Dec 2022 04:15:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1670760907; cv=none;
        d=google.com; s=arc-20160816;
        b=pVrvFUcEl44mpAGfHJJiNTZ14HkuaWF2q7Uhnkc+75Hlj5KFhKdxo4payy3+h3PwFe
         4cKI3tR8MN921bv2eEooXDXECxoHdO/HKMQOnS5yAPfBHFcRjav5WbFljSKF9n7bgbF/
         VrhqTIEUkna8uBZM5vDIRPAWQ6C36GBVaaZYcWp7df5m5ztPw9gHAsCpdthc2AOQmG0y
         z2x5DylqSinZV+InVB0/RVecFs14LnanoBKgHN1KayBBO9TcxMpKEM2Z/LWJy0AhPMGW
         fvXpf56Sd0PnGCztlDMaKdmmj4gICNqapyPanyzIJb/p8x+y0f2fqbIaNoyp8Bo/QUDt
         Nyog==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:from:cc:to:content-language:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=0/65jsHiJnNkwjkY49Ge2ZmtQq4CjJ+RG5OmMB+oBl8=;
        b=fjWCx9Xli+2ugE9VwQnfQuWh9ak6I4/kLfuIgpLjcjL5yL8oIWQ0+a4sZf1YSndrvs
         i9c/ckWIY1PfoGX+bAcQNDA5nNefpCj5pPlMrZkBgOuJ6BBVrMaDFzMwVnwodJamsUOj
         V8FJNwu/zReUKm/zAkiS1rh3/8b9GSUbVQPkNgbDWK35liY9dgYFMftd0ypUmvZyp/1k
         dkgdvgeyWJoA0u6iUxfINmJKCJdZAgaa4f6Fubb2OMOUbu73HkMPw2g2+I9rce8jaJUh
         D+GXhZ9chPXE1STcmMJrm3IcZGBqvOigoC5FD7yh/fsKJ5/BqtmP2CZ5ziv6bFdpl3eF
         nK5w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=YK7Hyy+5;
       spf=pass (google.com: domain of jgross@suse.com designates 195.135.220.28 as permitted sender) smtp.mailfrom=jgross@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.220.28])
        by gmr-mx.google.com with ESMTPS id f21-20020a7bcc15000000b003c4ecff4e2bsi211124wmh.1.2022.12.11.04.15.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 11 Dec 2022 04:15:07 -0800 (PST)
Received-SPF: pass (google.com: domain of jgross@suse.com designates 195.135.220.28 as permitted sender) client-ip=195.135.220.28;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 300D035334;
	Sun, 11 Dec 2022 12:15:07 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id F16A91376E;
	Sun, 11 Dec 2022 12:15:06 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id 3D1rOcrJlWOGEQAAMHmgww
	(envelope-from <jgross@suse.com>); Sun, 11 Dec 2022 12:15:06 +0000
Message-ID: <c18bc798-f484-ad66-fbb0-15192a74f8e3@suse.com>
Date: Sun, 11 Dec 2022 13:15:06 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.5.0
Content-Language: en-US
To: Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>,
 "xen-devel@lists.xenproject.org" <xen-devel@lists.xenproject.org>,
 =?UTF-8?Q?Marek_Marczykowski-G=c3=b3recki?=
 <marmarek@invisiblethingslab.com>,
 Demi Marie Obenour <demi@invisiblethingslab.com>
From: "'Juergen Gross' via kasan-dev" <kasan-dev@googlegroups.com>
Subject: kfence_protect_page() writing L1TF vulnerable PTE
Content-Type: multipart/signed; micalg=pgp-sha256;
 protocol="application/pgp-signature";
 boundary="------------ZRUJdiEHFWPIctjasAeGHXyx"
X-Original-Sender: jgross@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=susede1 header.b=YK7Hyy+5;       spf=pass
 (google.com: domain of jgross@suse.com designates 195.135.220.28 as permitted
 sender) smtp.mailfrom=jgross@suse.com;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=suse.com
X-Original-From: Juergen Gross <jgross@suse.com>
Reply-To: Juergen Gross <jgross@suse.com>
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

This is an OpenPGP/MIME signed message (RFC 4880 and 3156)
--------------ZRUJdiEHFWPIctjasAeGHXyx
Content-Type: multipart/mixed; boundary="------------PxzJOsklqGZLVS2TT8Wt8wCw";
 protected-headers="v1"
From: Juergen Gross <jgross@suse.com>
To: Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>,
 "xen-devel@lists.xenproject.org" <xen-devel@lists.xenproject.org>,
 =?UTF-8?Q?Marek_Marczykowski-G=c3=b3recki?=
 <marmarek@invisiblethingslab.com>,
 Demi Marie Obenour <demi@invisiblethingslab.com>
Message-ID: <c18bc798-f484-ad66-fbb0-15192a74f8e3@suse.com>
Subject: kfence_protect_page() writing L1TF vulnerable PTE

--------------PxzJOsklqGZLVS2TT8Wt8wCw
Content-Type: multipart/mixed; boundary="------------09GL24rRcr6QqZBnCeKOoI7R"

--------------09GL24rRcr6QqZBnCeKOoI7R
Content-Type: text/plain; charset="UTF-8"; format=flowed

During tests with QubesOS a problem was found which seemed to be related
to kfence_protect_page() writing a L1TF vulnerable page table entry [1].

Looking into the function I'm seeing:

	set_pte(pte, __pte(pte_val(*pte) & ~_PAGE_PRESENT));

I don't think this can be correct, as keeping the PFN unmodified and
just removing the _PAGE_PRESENT bit is wrong regarding L1TF.

There should be at least the highest PFN bit set in order to be L1TF
safe.


Juergen

[1]: https://github.com/QubesOS/qubes-issues/issues/7935

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c18bc798-f484-ad66-fbb0-15192a74f8e3%40suse.com.

--------------09GL24rRcr6QqZBnCeKOoI7R
Content-Type: application/pgp-keys; name="OpenPGP_0xB0DE9DD628BF132F.asc"
Content-Disposition: attachment; filename="OpenPGP_0xB0DE9DD628BF132F.asc"
Content-Description: OpenPGP public key
Content-Transfer-Encoding: quoted-printable

-----BEGIN PGP PUBLIC KEY BLOCK-----

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
jR/i1DG86lem3iBDXzXsZDn8R38=3D
=3D2wuH
-----END PGP PUBLIC KEY BLOCK-----

--------------09GL24rRcr6QqZBnCeKOoI7R--

--------------PxzJOsklqGZLVS2TT8Wt8wCw--

--------------ZRUJdiEHFWPIctjasAeGHXyx
Content-Type: application/pgp-signature; name="OpenPGP_signature.asc"
Content-Description: OpenPGP digital signature
Content-Disposition: attachment; filename="OpenPGP_signature"

-----BEGIN PGP SIGNATURE-----

wsB5BAABCAAjFiEEhRJncuj2BJSl0Jf3sN6d1ii/Ey8FAmOVycoFAwAAAAAACgkQsN6d1ii/Ey92
2Qf/TgMVuqQDkxg9jaeTZpkEDD0D9gh/np1oEiIpQHpvyGZdwlbCuYlEIn6f3VmlF9W4q3JVS1r0
Px1zaKCsHOvxWw2e3cv2ZZEgs6WTX881bdJBvWWxvuYmim2sHZ7QvSgL+5jJFfTjpWhpa262swie
7uglGNyp0dKhH8Mh2BdUxRQ2PYRyccgqMpjPL+Y9ZkkCIo3rsMrqXi1l7bE/rD72kBrAUj2Vh0Ci
US/qhHbN+9vrn6oRWq7YGMsEk08HMQ3gjOut9HaWhSKybSL/P3SKhdjzJNwX421RKsL8EsVL85Pk
EgMWHlecPEnEK+nnZJ/9cjMumELnMVD7umvlHvVsKQ==
=Hl4S
-----END PGP SIGNATURE-----

--------------ZRUJdiEHFWPIctjasAeGHXyx--
