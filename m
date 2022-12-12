Return-Path: <kasan-dev+bncBDB3VRMVXIPRB6PT3KOAMGQEWPOXCZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id D0ECF64989D
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Dec 2022 06:19:54 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id 9-20020a1c0209000000b003d1c0a147f6sf3621548wmc.4
        for <lists+kasan-dev@lfdr.de>; Sun, 11 Dec 2022 21:19:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1670822394; cv=pass;
        d=google.com; s=arc-20160816;
        b=G92UBfrNFYZACtunLI+BSYaVKhC3hRcJ+m9Az0lzMIMbEcz7WhHauFmEIInekSkr6B
         jnXVGOFjVMBb3yUSKa84BgVUseCRV02gQ4/2E61UXYCRxKZHLLYzSJ7PYIrfRBSkX/Qn
         hnL9DXMWz0mbvOwNEhqalP6AZqZ60Dj6qH+D78I4lRnehVl31wp89ucKfLImGTGAraRq
         lYHGQJClRGeo+slmlEBAv8Os2ZEChF7YS6FHyaZ9a2CX5xbGTIC2q2c+hon+LY+owR7c
         ukeyQRZkJ+gW5HLXslK05fpxwnnYxoH/r2UQ6x5OT3q7OU90zGVoaDKe77DY07m/XpgO
         ex8Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=fBygDZ8xXLzwLgkvmSUGAP9dPbCqLSYFD9vrsCzl7qw=;
        b=QDc+TXzpKi00ajYUBm0KZOlsG6qkJUQC7nGEphksWM76lznHjDGSGynscd+D7CVTZf
         MGVVCwjJ1Otc7EU2hpDo/5kC2HYe9ORiMx3buJBFtC54cHsulB5krnx7xpD/W3Iyx46Q
         hNFZatz0hGIJa708xdhFGtByMQnJvVbTLUQfPBH4b/NhmmZg1OgqeGiOcBj8ejnloUmp
         JsdpMJEs9i547BPv9PpTErae1ETIDAmmdgwyVvSLXUn75AC5gtteZhMITxVhRntDaTFL
         3GcZLO1oiws19yTwxRo6kS+CSevvKVvIcDePqRAzO7io2bsI5TJW/x6bRij9bSLjmrnm
         my7w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=NkcSmmuc;
       spf=pass (google.com: domain of jgross@suse.com designates 195.135.220.29 as permitted sender) smtp.mailfrom=jgross@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:from:to:cc:subject:date:message-id
         :reply-to;
        bh=fBygDZ8xXLzwLgkvmSUGAP9dPbCqLSYFD9vrsCzl7qw=;
        b=gkkJzvtwJA04XZF52eShNTomWTD5QjZe+MJ6d/p89ih4OdLLza4geqTdLCwC/Zcvn9
         BMvpPw2ww0dFE7jmKwP42tZyi7GYz0Gx7bEgp6r/tn9BXaqkgcYXMu4EtuoFxFDLuG+V
         LjdTUsda5eRe/DuEXh4HqHnlUhTG7BQ29BV78OVWVwd2zzJNzQLpyCTiCRLpePR/bFeR
         1YNtocX7Gb5mcBETgzC3SuOiTcl6ia+WoLFZdsLjTzMlCdr2aad025rpLjRoNTlvevc1
         2MsU1x0KEqCYr5DztGrouc7eqS2e3BM1ACrqXeSRJ2fHSOLEgWfhYBG8P2XMltruc6TH
         0LIg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:from:to:cc:subject
         :date:message-id:reply-to;
        bh=fBygDZ8xXLzwLgkvmSUGAP9dPbCqLSYFD9vrsCzl7qw=;
        b=yqxHT8EoRbSUsHmx1ZPw7YM08HmGf9gBahi19TC9nDBEechjlKiuZcEvP/POoZr9Ke
         NLOLURbrAQf60YDjCraHjWqIdX6w8CJY68iPC0hkkN2AP0LmqKXFkS4v3GTOIG9X+wWl
         ItaHwyqYxMqQv2oU5vr5wyLITvULeftUw706igFWfNoWg8wP+Pu0CA3CTrI3kpeAvbxO
         eb/kH8TXP6w89w438uvgoXIhNqXuu/47xgI2r1pEEy2NDrMEGZdW74w5MAe5tXmCygXV
         cbhP1BaPEEX8zn2B5eRivSqiRK3WfaI4o38zYv5sqvD0h4opV+X9AO/Kb9hLiHWJpAUp
         GF8A==
X-Gm-Message-State: ANoB5pmHqPi6garDeZJ3MQLNQMrXWx/KvWJl5irVJXEz1G5d1w7b/5Gx
	tle0C15tRvsJpJZWAMj6G/E=
X-Google-Smtp-Source: AA0mqf502wOnWoGseulonv4hIj2DI47ir8vE1Fow1A8XIewuB8C87Ysg08w+0LgCvXHOxckNFlvu8w==
X-Received: by 2002:a05:6000:81a:b0:242:6a15:e257 with SMTP id bt26-20020a056000081a00b002426a15e257mr9096498wrb.624.1670822394162;
        Sun, 11 Dec 2022 21:19:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:23b:b0:242:2700:8318 with SMTP id
 l27-20020a056000023b00b0024227008318ls5178881wrz.0.-pod-prod-gmail; Sun, 11
 Dec 2022 21:19:53 -0800 (PST)
X-Received: by 2002:adf:e283:0:b0:241:63d8:6741 with SMTP id v3-20020adfe283000000b0024163d86741mr8674773wri.9.1670822392902;
        Sun, 11 Dec 2022 21:19:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1670822392; cv=none;
        d=google.com; s=arc-20160816;
        b=ZNAd9ctpR14oSv5iHxTdue6iT8SjDUKAFFOI25yCypGiG8H4t55PluFC48GBm4lR7z
         ABNc4L0bUU8AmcJzEEPBICHWDqGBKpdbGUExq0osea4pLKJ1MKOh4xO57WejIH/U1KdG
         RZW4Zhd71nZ4iYQ5TEINtqfeJiSFiMhcXtmzt+TSnIa9uPdsjFCcBcUR1SPNTTNKM0yi
         5DKDuuvMqKeGvGpdUZJ+SakIbvaf3enGHBX0mjsfXP9GSYEcts2TO/7KbhNrNfdZRgVV
         gC8Nn+5ljrPpBkOs1EFOVWhA/9YHtIyNccxNMeBPVqiRp0wcKePZqzeo+0+1sefmWPnq
         I4bw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:from:references:cc:to:content-language:subject
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=xz5nnj3XD0YHenNz9nlFHXnTFZaUk+RI1pDMWcsUNJk=;
        b=qWJAbFTT3uyd4NgEwjENrPhM0sKe6ddVeRbXy1aYQwW7ACGrIjBdDBTX2/r6RDkVTI
         FKLc73kj6bYQcgrOqfT0sRF2i6xXvVVGrYVX4fJkSBVKDWyLVQgi2C/zwMb8SQ33RvO2
         kJA8EUVk07JVVDulSsRnOiPArNFba0cfIBcQ6/1HlobuOiMQqOV38HacHCERrow2Zy3a
         p2S4Nte+H5sKragPIhKI465BbB/pC2h2Cre5EyU0uWKDPI4vPgHPc+bYixzfaBm45KkN
         qcJ/SbRFSVvFJTlaSFuy3MrfbgVjE9FVux0VVheyo9z69qE8uMsVuxRyrDD/xsoVtNlO
         VIvw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=NkcSmmuc;
       spf=pass (google.com: domain of jgross@suse.com designates 195.135.220.29 as permitted sender) smtp.mailfrom=jgross@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.220.29])
        by gmr-mx.google.com with ESMTPS id ay17-20020a5d6f11000000b00241d0141fbcsi304517wrb.8.2022.12.11.21.19.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 11 Dec 2022 21:19:52 -0800 (PST)
Received-SPF: pass (google.com: domain of jgross@suse.com designates 195.135.220.29 as permitted sender) client-ip=195.135.220.29;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 8A0971FE19;
	Mon, 12 Dec 2022 05:19:52 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 4E1A51376E;
	Mon, 12 Dec 2022 05:19:52 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id vyWiEfi5lmOZQwAAMHmgww
	(envelope-from <jgross@suse.com>); Mon, 12 Dec 2022 05:19:52 +0000
Message-ID: <c250b8f5-bce5-da43-ae11-e5355141ea3c@suse.com>
Date: Mon, 12 Dec 2022 06:19:51 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.5.0
Subject: Re: kfence_protect_page() writing L1TF vulnerable PTE
Content-Language: en-US
To: Demi Marie Obenour <demi@invisiblethingslab.com>,
 Marco Elver <elver@google.com>
Cc: Alexander Potapenko <glider@google.com>,
 kasan-dev <kasan-dev@googlegroups.com>,
 Xen development discussion <xen-devel@lists.xenproject.org>,
 =?UTF-8?Q?Marek_Marczykowski-G=c3=b3recki?= <marmarek@invisiblethingslab.com>
References: <c18bc798-f484-ad66-fbb0-15192a74f8e3@suse.com>
 <Y5ZM3HCnTcLvP2vy@itl-email>
 <CANpmjNPZwtmMvAOk7rn9U=sWTre7+o93yB_0idkVCvJky6mptA@mail.gmail.com>
 <Y5azcFUxAWuEVicY@itl-email>
From: "'Juergen Gross' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <Y5azcFUxAWuEVicY@itl-email>
Content-Type: multipart/signed; micalg=pgp-sha256;
 protocol="application/pgp-signature";
 boundary="------------TDjy6sZearJP8RKYq0xs4s9P"
X-Original-Sender: jgross@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=susede1 header.b=NkcSmmuc;       spf=pass
 (google.com: domain of jgross@suse.com designates 195.135.220.29 as permitted
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
--------------TDjy6sZearJP8RKYq0xs4s9P
Content-Type: multipart/mixed; boundary="------------jmu50pFsK3nFV6dYJ1cupCTv";
 protected-headers="v1"
From: Juergen Gross <jgross@suse.com>
To: Demi Marie Obenour <demi@invisiblethingslab.com>,
 Marco Elver <elver@google.com>
Cc: Alexander Potapenko <glider@google.com>,
 kasan-dev <kasan-dev@googlegroups.com>,
 Xen development discussion <xen-devel@lists.xenproject.org>,
 =?UTF-8?Q?Marek_Marczykowski-G=c3=b3recki?= <marmarek@invisiblethingslab.com>
Message-ID: <c250b8f5-bce5-da43-ae11-e5355141ea3c@suse.com>
Subject: Re: kfence_protect_page() writing L1TF vulnerable PTE
References: <c18bc798-f484-ad66-fbb0-15192a74f8e3@suse.com>
 <Y5ZM3HCnTcLvP2vy@itl-email>
 <CANpmjNPZwtmMvAOk7rn9U=sWTre7+o93yB_0idkVCvJky6mptA@mail.gmail.com>
 <Y5azcFUxAWuEVicY@itl-email>
In-Reply-To: <Y5azcFUxAWuEVicY@itl-email>

--------------jmu50pFsK3nFV6dYJ1cupCTv
Content-Type: multipart/mixed; boundary="------------oZhaDNPkkcoxk2G0lwcWLKjd"

--------------oZhaDNPkkcoxk2G0lwcWLKjd
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable

On 12.12.22 05:55, Demi Marie Obenour wrote:
> -----BEGIN PGP SIGNED MESSAGE-----
> Hash: SHA512
>=20
> - -----BEGIN PGP SIGNED MESSAGE-----
> Hash: SHA512
>=20
> On Sun, Dec 11, 2022 at 11:50:39PM +0100, Marco Elver wrote:
>> On Sun, 11 Dec 2022 at 22:34, Demi Marie Obenour
>> <demi@invisiblethingslab.com> wrote:
>>> On Sun, Dec 11, 2022 at 01:15:06PM +0100, Juergen Gross wrote:
>>>> During tests with QubesOS a problem was found which seemed to be relat=
ed
>>>> to kfence_protect_page() writing a L1TF vulnerable page table entry [1=
].
>>>>
>>>> Looking into the function I'm seeing:
>>>>
>>>>        set_pte(pte, __pte(pte_val(*pte) & ~_PAGE_PRESENT));
>>>>
>>>> I don't think this can be correct, as keeping the PFN unmodified and
>>>> just removing the _PAGE_PRESENT bit is wrong regarding L1TF.
>>>>
>>>> There should be at least the highest PFN bit set in order to be L1TF
>>>> safe.
>=20
>> Could you elaborate what we want to be safe from?
>=20
> The problem is not Linux=E2=80=99s safety, but Xen=E2=80=99s.  To prevent=
 PV guests from
> arbitrarily reading and writing memory, all updates to PV guest page
> tables must be done via hypercalls.  This allows Xen to ensure that a
> guest can only read from its own memory and that pages used for page
> tables or segment descriptors are not mapped writable.
>=20
>> KFENCE is only for kernel memory, i.e. slab allocations. The
>> page-protection mechanism is used to detect memory safety bugs in the
>> Linux kernel. The page protection does not prevent or mitigate any
>> such bugs because KFENCE only samples sl[au]b allocations. Normal slab
>> allocations never change the page protection bits; KFENCE merely uses
>> them to receive a page fault, upon which we determine either a
>> use-after-free or out-of-bounds access. After a bug is detected,
>> KFENCE unprotects the page so that the kernel can proceed "as normal"
>> given that's the state of things if it had been a normal sl[au]b
>> allocation.
>=20
>> https://docs.kernel.org/dev-tools/kfence.html
>=20
>>  From [1] I see: "If an instruction accesses a virtual address for
>> which the relevant page table entry (PTE) has the Present bit cleared
>> or other reserved bits set, then speculative execution ignores the
>> invalid PTE and loads the referenced data if it is present in the
>> Level 1 Data Cache, as if the page referenced by the address bits in
>> the PTE was still present and accessible."
>=20
>> [1] https://www.kernel.org/doc/html/latest/admin-guide/hw-vuln/l1tf.html
>=20
>> This is perfectly fine in the context of KFENCE, as stated above, the
>> page protection is merely used to detect out-of-bounds and
>> use-after-free bugs of sampled slab allocations. KFENCE does not
>> mitigate nor prevent such bugs, because it samples allocations, i.e.
>> most allocations are still serviced by sl[au]b.
>=20
> It is not fine when running paravirtualized under Xen, though.  Xen
> strictly validates that present PTEs point into a guest=E2=80=99s own mem=
ory,
> but (in the absence of L1TF) allows not-present PTEs to have any value.
> However, L1TF means that doing so would allow a PV guest to leak memory
> from Xen or other guests!  Therefore, Xen requires that not-present PTEs
> be L1TF-safe, ensuring that PV guests cannot use L1TF to obtain memory
> from other guests or the hypervisor.
>=20
> If a guest creates an L1TF-vulnerable PTE, Xen=E2=80=99s behavior depends=
 on
> whether it has been compiled with shadow paging support.  If it has, Xen
> will transition the guest to shadow paging mode.  This works, but comes
> at a significant performance hit, so you don=E2=80=99t want that.  If sha=
dow
> paging has been disabled at compile time, as is the case in Qubes, Xen
> simply crashes the guest.
>=20
> dom0 is exempted from these checks by default, because the dom0 kernel
> is considered trusted.  However, this can be changed by a Xen
> command-line option, so it is not to be relied on.
>=20
>> How can we teach whatever is complaining about L1TF on that KFENCE PTE
>> modification that KFENCE does not use page protection to stop anyone
>> from accessing that memory?
>=20
> With current Xen, you can=E2=80=99t.  Any not-present PTE must be L1TF-sa=
fe on
> L1TF-vulnerable hardware, and I am not aware of any way to ask Xen if it
> considers the hardware vulnerable to L1TF.  Therefore, KFENCE would need
> to either not generate L1TF-vulnerable not-present PTEs, or
> automatically disable itself when running in Xen PV mode.
>=20
> In theory, it ought to be safe for Xen to instead treat not-present
> L1TF-vulnerable PTEs as if they were present, and apply the same
> validation that it does for present PTEs.  However, the PV memory
> management code has been involved in several fatal, reliably exploitable
> PV guest escape vulnerabilities, and I would rather not make it any more
> complex than it already is.

Treating non-present PTEs like present ones has a major drawback: it
requires to keep track of all page frames being potentially referenced,
inducing a major performance hit for the "regular" case. Memory ballooning
would be a lot more complicated due to that.

> A much better solution would be for KFENCE to use PTE inversion just
> like the rest of the kernel does.  This solves the problem
> unconditionally, and avoids needing Xen PV specific code.  I have a
> patch that disables KFENCE on Xen PV, but I would much rather see KFENCE
> fixed, which is why I have not submitted the patch.

I can supply a kernel patch for doing the PFN inversion in the PTE.


Juergen

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/c250b8f5-bce5-da43-ae11-e5355141ea3c%40suse.com.

--------------oZhaDNPkkcoxk2G0lwcWLKjd
Content-Type: application/pgp-keys; name="OpenPGP_0xB0DE9DD628BF132F.asc"
Content-Disposition: attachment; filename="OpenPGP_0xB0DE9DD628BF132F.asc"
Content-Description: OpenPGP public key
Content-Transfer-Encoding: quoted-printable

-----BEGIN PGP PUBLIC KEY BLOCK-----

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
jR/i1DG86lem3iBDXzXsZDn8R38=3D
=3D2wuH
-----END PGP PUBLIC KEY BLOCK-----

--------------oZhaDNPkkcoxk2G0lwcWLKjd--

--------------jmu50pFsK3nFV6dYJ1cupCTv--

--------------TDjy6sZearJP8RKYq0xs4s9P
Content-Type: application/pgp-signature; name="OpenPGP_signature.asc"
Content-Description: OpenPGP digital signature
Content-Disposition: attachment; filename="OpenPGP_signature"

-----BEGIN PGP SIGNATURE-----

wsB5BAABCAAjFiEEhRJncuj2BJSl0Jf3sN6d1ii/Ey8FAmOWufcFAwAAAAAACgkQsN6d1ii/Ey+H
jQgAg7nHsWFzaEfFwDmTTypBIAuAAPfDYyBHkexDtDZtX7CdAndNjjhgKxeCRoMkPrpkK1o06Bin
ppU/wpU6cnEzadUU7Vb2HqL+Y5mk7FsjTHYm33f/1w+ceeufd9o+FRlGJSM1mKR/c3rr1VWI4Z/B
+hjWdwO8KU/AvTySTqx+BzCTVcUgyca37cJXsf/0wrUzMV82cLcmq6aPPNrw948gYjvoplxugisn
lL0gp3FdZr79m7LaRLJkUWuTEPOixY+uFcJkY2dqGCAVws6DF3rdav8gxFWJ0Onlb69ffj+Um7CY
T4jinfTPN9eBYjY9YTIPqAs+JDTFDrbs+Od51md/nw==
=2sp0
-----END PGP SIGNATURE-----

--------------TDjy6sZearJP8RKYq0xs4s9P--
