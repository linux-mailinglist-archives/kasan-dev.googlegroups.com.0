Return-Path: <kasan-dev+bncBCW4XEU3YIIRBKXI3KOAMGQEJXRNBXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63f.google.com (mail-ej1-x63f.google.com [IPv6:2a00:1450:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 54668649880
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Dec 2022 05:55:07 +0100 (CET)
Received: by mail-ej1-x63f.google.com with SMTP id gn28-20020a1709070d1c00b007c177fee5fasf394730ejc.23
        for <lists+kasan-dev@lfdr.de>; Sun, 11 Dec 2022 20:55:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1670820907; cv=pass;
        d=google.com; s=arc-20160816;
        b=fq9b5csfOPIbBeHIe0C8bMpVcQH2Ds1UIzNE40y1QRSxRwAeLjby18tsdz3eoL4H2+
         Kkm33zJzH8ng7vm/KfQ6gtnsz2yw0cqGIHiB54O9jmFdcFn1eLQ7SsnXasdm+Lfhor6a
         +9uBdbYAep1YLE5TdYBLCc7UBTks6TgRv9EAuEqcXNqfYTNPQFFA5ZtI7rkJMhUqq8r5
         oHnD3fYatnIZ4GJ0Gb6T6jIIJFEJ1AlvGTvoumIacVgW4vf1P4KZiVFMc2D1dGXWIYmE
         qiM54/JExhVdhb7Q496XTeCt5DN7abLqweRYo2gyjCThP9s+Ro4V965XaadqHX+xxiip
         TSlQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:mime-version:references:message-id
         :subject:cc:to:from:date:feedback-id:sender:dkim-signature;
        bh=7CWLDqBk5Z4Ya7sxHS34af4m+L5bHapw+36Wqu+SYqk=;
        b=ZL8rbwacLrK05e61nTHnKt/OXhAu4SKhoxzjsPUOKtgf9Ji/4dn4HHFd6rGWz+/oX7
         jbs4UJgudP6qni7hFgdvKzvSQ0F+gSxYKILpRX5BkvoFgOZU2A+8g2+FyOO/X56FDZ8q
         1XOdr251yn/UHS8dklbrj2rwSIFD7UuN0JEo2u8HNbhKqeP4PPa/oMyFN9EGQJbkLHGz
         Lqjl79bMQ2ehwBydgVZO4zI9sIHpsQriUgYHOLDhVYePHX6RwdD48KAEYPTQ2jnZSaYq
         HuuFG4EvqHsSThqGEhGv8uvaq/YKi+iNi8wwXnUUuceabcubQHKqe5QKNDog/AaSm+qS
         6SeQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@invisiblethingslab.com header.s=fm1 header.b=pMhY8wns;
       dkim=pass header.i=@messagingengine.com header.s=fm2 header.b=XBeU2CBA;
       spf=neutral (google.com: 64.147.123.25 is neither permitted nor denied by best guess record for domain of demi@invisiblethingslab.com) smtp.mailfrom=demi@invisiblethingslab.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :mime-version:references:message-id:subject:cc:to:from:date
         :feedback-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=7CWLDqBk5Z4Ya7sxHS34af4m+L5bHapw+36Wqu+SYqk=;
        b=ZnwkuT173+JQ1RckQKXqWAGlJicueZievmvJYg1FFsjGWujNSeMP+gyk6p1fZB7uoB
         GAWrPWrENUw7OmYQW3rDmq+RWSziDZT8soTMFiZd+/q0zik/VduGJcIIQNPi9LmTqEVi
         Nvmkf59H7fdbdl6gFvLljGjtFSO/lCTKH+kRmwVMEDRAAgjtRfexPQwzoiGIIwOttNJM
         0HFV9d3IbeFCoSwGjpvaBGWSxGHxw2/xIXsRgPBEh0VplwwQEQlFhT3CG/cJjIADy66H
         cIg093eA885BaxpZOgMrod1bFlZPmo1yIb431RF1JPEVrzfdXOoyQnuknKTaeKcgdAfJ
         /u/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:mime-version:references:message-id
         :subject:cc:to:from:date:feedback-id:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=7CWLDqBk5Z4Ya7sxHS34af4m+L5bHapw+36Wqu+SYqk=;
        b=IlX7pzvFAjknirH1+hMVYpXdBrCyZHkonCDoh8LTIh4z6O5FRODMvX5E6RjatqY3aT
         zvVO/UFaTLWEoAig7UHh/PDGDpkg4BmwPvQpcSJIhrmeFYXmUKcdsTeuPlum+2nBimui
         infN8vdRJEg+XDgBny7Ha0acHxiU/SEMhqgFvqqXcVGdwnbAPKoP+xo1cvnwYgt/fp8H
         mFrMPHrDNsEhrkQTxhau0WZP8vU6V2EgfIj1LMGDAx3WCL/8G/GSl1AmHR4o5vB1eDAu
         GpKPx3jjV9r6OkGN1FMjMEr1GZwIIY+zYEzK+Ca0x2VKkGEdCj3VmzNG9/SSv0lnq69K
         IQFQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5plV5+oiwqSVwstKyKiVVej1Iie+XwKXhPBwbU3TGpnwiKW1lPbI
	mje7WwBBml8U9cMYGAGsrws=
X-Google-Smtp-Source: AA0mqf54nwZwu93a/QE9pCGEJNwC/qWyVqdZY8AXiJnekAao1QsjimHk5DJyWlsGm7kGgzL+JS20uQ==
X-Received: by 2002:aa7:da10:0:b0:46c:43ff:6961 with SMTP id r16-20020aa7da10000000b0046c43ff6961mr23363539eds.14.1670820906744;
        Sun, 11 Dec 2022 20:55:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:190a:b0:45c:bfd9:fb45 with SMTP id
 e10-20020a056402190a00b0045cbfd9fb45ls1313039edz.3.-pod-prod-gmail; Sun, 11
 Dec 2022 20:55:05 -0800 (PST)
X-Received: by 2002:a05:6402:294d:b0:45c:cd16:aeae with SMTP id ed13-20020a056402294d00b0045ccd16aeaemr12462317edb.13.1670820905623;
        Sun, 11 Dec 2022 20:55:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1670820905; cv=none;
        d=google.com; s=arc-20160816;
        b=JFR2vakFWMUmeaVKOeYICfEqU7oLcQUCm1sxxKN4gl5GRSfKh+TOJIVf0QeDUm0rJE
         43qkEApWZYR6JD/MPAG/6hlBATaO2q5nprenj1fFUdqiwXHP+34/YVt5oyb5JKvFvRTT
         pbp5Z00EEn7BffLKiYPK4xnPIj9PZxrztzqQLx9n15nuFROVBMeSVDAi0eKPRC2Mr15J
         aWQa0CDnjx0+5NN0aEejG9nfbsjcsCKyNC91ueLMAh30HklIvmfGXCzA0rfPSS+P9DfL
         Po+e7pCxaz+6TYEdD6/OYS1aEWAhH48ffPRs/CESMuMVQ4DEAlmgxkBFDxpUStcR9Rqr
         TTEA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:mime-version:references
         :message-id:subject:cc:to:from:date:feedback-id:dkim-signature
         :dkim-signature;
        bh=/fhhuNHSw9AVcLNazlLsxWzz1tsOBeVmZMRVG4LPq0o=;
        b=eFM3lh5ZiflYS2C63lg9KE6HJNWh6wL1x2ULYxiThkGAdW+hleS7jvcmRBhvgS1pDC
         EVfIaQGRud8VmGwP7DMzU2RBjHj+vhLpz3gBvxurxzXJ/zUKHCfOoLBuO+qkOWa+Gj6d
         1ivp67oOGQ1Udbjnf9hsFAG1MmZwSNf95C260w/jYwkva+bGZ9Prco/By5JyqtP48TmU
         /hxNq51zOujwtpbem7spGmcKrs+0Ux52C8eHLDQ5xHM8Jz75VQkPphrBzNaL6rN5qh93
         2ZdEkVAp7vkd/3UnquZn4GlHjuxNu7kuWrpHFg1YlYfko1vz6sZrmKfRLTOPNBdYOjBC
         LtLw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@invisiblethingslab.com header.s=fm1 header.b=pMhY8wns;
       dkim=pass header.i=@messagingengine.com header.s=fm2 header.b=XBeU2CBA;
       spf=neutral (google.com: 64.147.123.25 is neither permitted nor denied by best guess record for domain of demi@invisiblethingslab.com) smtp.mailfrom=demi@invisiblethingslab.com
Received: from wout2-smtp.messagingengine.com (wout2-smtp.messagingengine.com. [64.147.123.25])
        by gmr-mx.google.com with ESMTPS id t25-20020aa7d4d9000000b004621a13c733si454468edr.1.2022.12.11.20.55.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 11 Dec 2022 20:55:05 -0800 (PST)
Received-SPF: neutral (google.com: 64.147.123.25 is neither permitted nor denied by best guess record for domain of demi@invisiblethingslab.com) client-ip=64.147.123.25;
Received: from compute4.internal (compute4.nyi.internal [10.202.2.44])
	by mailout.west.internal (Postfix) with ESMTP id 35E0932008FA;
	Sun, 11 Dec 2022 23:55:03 -0500 (EST)
Received: from mailfrontend2 ([10.202.2.163])
  by compute4.internal (MEProxy); Sun, 11 Dec 2022 23:55:03 -0500
X-ME-Sender: <xms:JrSWY64mizyAnnLG0UqXDbPpe5ApUi5_wnPS-zyFZ4Ho4xKDz0cT1A>
    <xme:JrSWYz7oXaDYIqqbpGb57TrX8o8qB2faIwTmpCWHkrIMuwKDQ8qlVCjfmUIGUB42P
    5pMRfmIb9fUHxE>
X-ME-Received: <xmr:JrSWY5fuK3sbxtp-gvxHaPxhO_Ne2Aty7UfTaTMGhyXxtTgxInPUf_RBwf5Y>
X-ME-Proxy-Cause: gggruggvucftvghtrhhoucdtuddrgedvhedrvdejgdejiecutefuodetggdotefrodftvf
    curfhrohhfihhlvgemucfhrghsthforghilhdpqfgfvfdpuffrtefokffrpgfnqfghnecu
    uegrihhlohhuthemuceftddtnecusecvtfgvtghiphhivghnthhsucdlqddutddtmdenuc
    fjughrpeffhffvvefukfhfgggtgfgjsehtqhertddttdejnecuhfhrohhmpeffvghmihcu
    ofgrrhhivgcuqfgsvghnohhurhcuoeguvghmihesihhnvhhishhisghlvghthhhinhhgsh
    hlrggsrdgtohhmqeenucggtffrrghtthgvrhhnpeejudfgieeviedtgfdvheejueefkeef
    tdetffejfeduteehhfetuedtieffvdejffenucffohhmrghinhepkhgvrhhnvghlrdhorh
    hgnecuvehluhhsthgvrhfuihiivgeptdenucfrrghrrghmpehmrghilhhfrhhomhepuggv
    mhhisehinhhvihhsihgslhgvthhhihhnghhslhgrsgdrtghomh
X-ME-Proxy: <xmx:JrSWY3KsJxTJPYAyrWLlJmtt9_0jmAz5fTYbKIdYAwTd3pKk7-vPNw>
    <xmx:JrSWY-KcLkuKcnhY2IizoIGyF7mZOzAuL3Z4nya1hGOsMVBSuvwAnQ>
    <xmx:JrSWY4x0CgGC4jvxwPwpgeKe1lS-i0DZQSHDPQKctFJyAnX0o1WQ1A>
    <xmx:JrSWY61foFJPSAB_Y0OSh52C_mGFCjhzv15iDrJ8qcTrOvvPJXWqXQ>
Feedback-ID: iac594737:Fastmail
Received: by mail.messagingengine.com (Postfix) with ESMTPA; Sun,
 11 Dec 2022 23:55:02 -0500 (EST)
Date: Sun, 11 Dec 2022 23:55:00 -0500
From: Demi Marie Obenour <demi@invisiblethingslab.com>
To: Marco Elver <elver@google.com>
Cc: Juergen Gross <jgross@suse.com>,
	Alexander Potapenko <glider@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Xen development discussion <xen-devel@lists.xenproject.org>,
	Marek =?utf-8?Q?Marczykowski-G=C3=B3recki?= <marmarek@invisiblethingslab.com>
Subject: Re: kfence_protect_page() writing L1TF vulnerable PTE
Message-ID: <Y5azcFUxAWuEVicY@itl-email>
References: <c18bc798-f484-ad66-fbb0-15192a74f8e3@suse.com>
 <Y5ZM3HCnTcLvP2vy@itl-email>
 <CANpmjNPZwtmMvAOk7rn9U=sWTre7+o93yB_0idkVCvJky6mptA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"; x-action=pgp-signed
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CANpmjNPZwtmMvAOk7rn9U=sWTre7+o93yB_0idkVCvJky6mptA@mail.gmail.com>
X-Original-Sender: demi@invisiblethingslab.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@invisiblethingslab.com header.s=fm1 header.b=pMhY8wns;
       dkim=pass header.i=@messagingengine.com header.s=fm2 header.b=XBeU2CBA;
       spf=neutral (google.com: 64.147.123.25 is neither permitted nor denied
 by best guess record for domain of demi@invisiblethingslab.com) smtp.mailfrom=demi@invisiblethingslab.com
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

-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

- -----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

- - -----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

On Sun, Dec 11, 2022 at 11:50:39PM +0100, Marco Elver wrote:
> On Sun, 11 Dec 2022 at 22:34, Demi Marie Obenour
> <demi@invisiblethingslab.com> wrote:
> > On Sun, Dec 11, 2022 at 01:15:06PM +0100, Juergen Gross wrote:
> > > During tests with QubesOS a problem was found which seemed to be rela=
ted
> > > to kfence_protect_page() writing a L1TF vulnerable page table entry [=
1].
> > >
> > > Looking into the function I'm seeing:
> > >
> > >       set_pte(pte, __pte(pte_val(*pte) & ~_PAGE_PRESENT));
> > >
> > > I don't think this can be correct, as keeping the PFN unmodified and
> > > just removing the _PAGE_PRESENT bit is wrong regarding L1TF.
> > >
> > > There should be at least the highest PFN bit set in order to be L1TF
> > > safe.
>=20
> Could you elaborate what we want to be safe from?

The problem is not Linux=E2=80=99s safety, but Xen=E2=80=99s.  To prevent P=
V guests from
arbitrarily reading and writing memory, all updates to PV guest page
tables must be done via hypercalls.  This allows Xen to ensure that a
guest can only read from its own memory and that pages used for page
tables or segment descriptors are not mapped writable.

> KFENCE is only for kernel memory, i.e. slab allocations. The
> page-protection mechanism is used to detect memory safety bugs in the
> Linux kernel. The page protection does not prevent or mitigate any
> such bugs because KFENCE only samples sl[au]b allocations. Normal slab
> allocations never change the page protection bits; KFENCE merely uses
> them to receive a page fault, upon which we determine either a
> use-after-free or out-of-bounds access. After a bug is detected,
> KFENCE unprotects the page so that the kernel can proceed "as normal"
> given that's the state of things if it had been a normal sl[au]b
> allocation.
>=20
> https://docs.kernel.org/dev-tools/kfence.html
>=20
> From [1] I see: "If an instruction accesses a virtual address for
> which the relevant page table entry (PTE) has the Present bit cleared
> or other reserved bits set, then speculative execution ignores the
> invalid PTE and loads the referenced data if it is present in the
> Level 1 Data Cache, as if the page referenced by the address bits in
> the PTE was still present and accessible."
>=20
> [1] https://www.kernel.org/doc/html/latest/admin-guide/hw-vuln/l1tf.html
>=20
> This is perfectly fine in the context of KFENCE, as stated above, the
> page protection is merely used to detect out-of-bounds and
> use-after-free bugs of sampled slab allocations. KFENCE does not
> mitigate nor prevent such bugs, because it samples allocations, i.e.
> most allocations are still serviced by sl[au]b.

It is not fine when running paravirtualized under Xen, though.  Xen
strictly validates that present PTEs point into a guest=E2=80=99s own memor=
y,
but (in the absence of L1TF) allows not-present PTEs to have any value.
However, L1TF means that doing so would allow a PV guest to leak memory
from Xen or other guests!  Therefore, Xen requires that not-present PTEs
be L1TF-safe, ensuring that PV guests cannot use L1TF to obtain memory
from other guests or the hypervisor.

If a guest creates an L1TF-vulnerable PTE, Xen=E2=80=99s behavior depends o=
n
whether it has been compiled with shadow paging support.  If it has, Xen
will transition the guest to shadow paging mode.  This works, but comes
at a significant performance hit, so you don=E2=80=99t want that.  If shado=
w
paging has been disabled at compile time, as is the case in Qubes, Xen
simply crashes the guest.

dom0 is exempted from these checks by default, because the dom0 kernel
is considered trusted.  However, this can be changed by a Xen
command-line option, so it is not to be relied on.

> How can we teach whatever is complaining about L1TF on that KFENCE PTE
> modification that KFENCE does not use page protection to stop anyone
> from accessing that memory?

With current Xen, you can=E2=80=99t.  Any not-present PTE must be L1TF-safe=
 on
L1TF-vulnerable hardware, and I am not aware of any way to ask Xen if it
considers the hardware vulnerable to L1TF.  Therefore, KFENCE would need
to either not generate L1TF-vulnerable not-present PTEs, or
automatically disable itself when running in Xen PV mode.

In theory, it ought to be safe for Xen to instead treat not-present
L1TF-vulnerable PTEs as if they were present, and apply the same
validation that it does for present PTEs.  However, the PV memory
management code has been involved in several fatal, reliably exploitable
PV guest escape vulnerabilities, and I would rather not make it any more
complex than it already is.

A much better solution would be for KFENCE to use PTE inversion just
like the rest of the kernel does.  This solves the problem
unconditionally, and avoids needing Xen PV specific code.  I have a
patch that disables KFENCE on Xen PV, but I would much rather see KFENCE
fixed, which is why I have not submitted the patch.
- - - --=20
Sincerely,
Demi Marie Obenour (she/her/hers)
Invisible Things Lab
- - -----BEGIN PGP SIGNATURE-----

iQIzBAEBCgAdFiEEdodNnxM2uiJZBxxxsoi1X/+cIsEFAmOWs28ACgkQsoi1X/+c
IsEvBQ/+MLAfhKAxmMAto9jII+4SIq6vXHvhNJfC+qyMPCToTI1QLiwGLOAXM7uk
nrnFh+eA9Tx1iYJyP6jZpKqWHFLtXNIh+QE+6gag1rMYjCeJyl6Y0bgmxw7EgJ4t
uACncw+N72CopWu9Yg2YNH9wahX7EX4/q+3FA2xzsYd/XgXOEVEF9h3vgnzDOVTJ
02/Q4c4P/YH+I0aLkD3lamwdBTeE2f+5h+kDFxib/qu1lHLVbC9Lx45/T2dUoWVa
K3uRPAzwwLQcxB1Q8wGHKj7ziEwygqKRoD8QYwMU67OdB0UsTQ+f5hH8JUgevm8V
po0T/cQDaAnJi0y9jcjUd4eyeOHZmbzjro+YAqOgkGGhs+TJwhU5VuDHD26z+0g3
dRaunQ7YFWrEFbeAmV0hK39x40nRdR42YRj6Q/uYhZcaORDeG+e5FshyeUesQfDW
B9r5Lvl6/V0ldgPHL/AyGFI/fZBUJhju3QyXNLML1xrv19j24Ku+bhKDjxSrHYlJ
nvxYo6zFhMkgRxTYNIrZUA70Xn3wDtJwFKGlKNmWRy4Hjfxy2tyIQnp00j+MDseY
fftXjlAPxm0am3lYHlp4u3L5hK1aY0l0mCdGjjP7geeEKK9f2Q009uTeywavOkAB
bAKQ9VNWrj7SlRhbK86sHi0zYTvNN+tF9/x32jUu1lSz+jyMfLM=3D
=3D3TnU
- - -----END PGP SIGNATURE-----
- -----BEGIN PGP SIGNATURE-----

iQIzBAEBCgAdFiEEdodNnxM2uiJZBxxxsoi1X/+cIsEFAmOWs/wACgkQsoi1X/+c
IsGDew/8DrvkeG5llY9Q9NFXfBPCNeu5WfK2Sbll892izQAl0l+JILKHG7AQqsRf
/avO3U5US64acEsL2PqugK1BDDYPK097WNJtV3/nb6IUL+A3UrMtq3a6bqCWMULY
FaCTqAe9ESYLS2NA4rqcqsCvGcR0PYM8fALqq+xHUr102rXyo+jGoOxCh6emuImg
UittOmEhslRtIJtiDgUHgQkff8xBllztVE1MaDeMIEO2D+uvKWD+7SYli+O3USAj
lNKlVPzHAwQnUs9AP++FVz0yVzcoyXcIsi14oFxSHR+EqqacxvtG60iWKcU6I8nr
zySMyjlN8rZcq/QpukYFAPkJL63m1zefHBWeLFzNcv5Mrar0L4cWpM+jLZyh/fJE
JQ2YuDt8Z5mhrs8KQJBdf96QSgOgkreMQ6IWNnPGiAwIW85wwsU1iJa8AjIEe8PN
t4EleqLqsgn9nihBreJZ77f/xKAWKK/VN6FOXGOuFZO/FrvPpP0KAHQpRugMmDZk
NOGJKcWfruAZ11HQTFK1qelLg0n2SBSzw5KxKyxntazvx80W+FzwwzJJz2T3z06g
58sCdyXqrzhSv55pfTX94suX+w3pqcwJID/XMjelPtvcVtvosugHmaCEKTHEX5zo
QKZRoHELiOymXsy7kSP8NMpiuyfrjAsYFY2NGbTS5Mb6+ApHT2s=3D
=3DgX1O
- -----END PGP SIGNATURE-----
-----BEGIN PGP SIGNATURE-----

iQIzBAEBCgAdFiEEdodNnxM2uiJZBxxxsoi1X/+cIsEFAmOWtCMACgkQsoi1X/+c
IsGPlQ//QaynWUjFxss7xGDDU3adTawbb5KHgxcaHQKsUCgDMqOYZ6wIm6VeiBgJ
OxX14wucGTKVYN0JSMqn1UpJgxVmMtwMTXMuIjz+oTdd3Ab/cQejqGV2ZiiW/KWH
Hq3jWqoqXL9R0sMmGmeq2Kyi1+XL78KhWZIkJ4eEKYhRdLIG9/q27EeH3ppdH6Kt
AamU0Bq1aatOW3+Y6C+FPjsLrHP16vWZInaoy+UqE0E7B4VcAC2wPcPVbwbF7SJc
KP4YaE3W95Zvl7TWxtOWWzZzKP3A6waiyY289+Kf7Xgs2rQOgNnQuR5JEGqxABwZ
LfbATY1uT9akgf62IevmGj3694ZPLVfgqr3d7057QfMCZLjAG5ZioIzCe7drCZ+3
91zM0+ykWYIqanab327lpduOkHHSJC0P1Jvzx4yxqo1PvgqhEHhp3jcXS6amCm9e
l4RVmAVm+UujZ1vbrTG7PcJgb5jbrtLKInhmYiiXGgS1zhxsty/MUCiy5YgjD5n1
vl+8/8/kiI4el/hjbqUbDjjItDmHn9kVZHfY5G1dT6lHZkNk6NI93IB6EcxZx1af
fNoxR904M7Y53yUI1sJpdeOhEsNHUeV5dgqbJxwTxKRuDNu4E89FDvRr3YMSbusk
7nU6+DVJaWRn05lq0lT2HsU401ECx383Pr5/lmvHCRdNuEOTwyo=3D
=3DjVTg
-----END PGP SIGNATURE-----

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/Y5azcFUxAWuEVicY%40itl-email.
