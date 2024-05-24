Return-Path: <kasan-dev+bncBDKMZTOATIBRBKE5YOZAMGQEBYDGM5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 0797A8CE932
	for <lists+kasan-dev@lfdr.de>; Fri, 24 May 2024 19:30:18 +0200 (CEST)
Received: by mail-wr1-x43f.google.com with SMTP id ffacd0b85a97d-354f9b5f1d1sf231457f8f.1
        for <lists+kasan-dev@lfdr.de>; Fri, 24 May 2024 10:30:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1716571817; cv=pass;
        d=google.com; s=arc-20160816;
        b=TSBHewuPwmph03pJjqXi4qwD3NSZmDuzPb1WhN59xHbjOUDqQDsX98vwdAYjT+y/pu
         Y/Dx4i+Su2FNsS+QE2eneyodldxT+0XR6kg4bOOiSGK5oF44u6IYy0FERnTvHU1VGAkq
         SPcXtrDwqFnIXM8/AvtoZRaifL++VMcpx/JzaiXOdUEHRVW7V1DSvnVAX8lTuVUFQVPy
         1P4CBJmDeqKsb/i+JVyS7mfU0lWGe0dap99S6xUXdbsbDoIMfYYdHV2icZWjaRr1gJb/
         aelLqW50Mo+XqaDSEz4aiw6PCjUmo6yEazmYWlGpeJjQXI2XH3fadhdmlxIqA6HM9zks
         EezQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=86BOCwd7DdwJ4EePkPDoIjsZMVuT4FMoK/qXuNA4abg=;
        fh=ZYeDXH4XOQdlGuBhsKGrv2CDSOa4EdnKEVfu26fiXD4=;
        b=Gf/HQwXXRvx61KyMMlyMh0/I/4fcvE+n/voj/SamLnRcDvaGtUGYkP6Ten2Fa2ZgX0
         XANSt05hyT8cJVg4YW6+DwnZur0iUiEwzrgkVxaQMbqHr+bOM98Qp4YO2kwpKyAK8g0c
         otHQuwlBNvTCW9rb/phk9XR+TCv8Q73akuW/JbaNap+1vkKLWFL+ujoVCpnz0EwoWcvT
         8xk7F16TdNF3FfXBRXfK/D+Twx30iDsc+fqQzn6nnYza6MnvmewCUkokhba2280Lw72p
         mQl87aqawqtvByAL7M4pfTUBOL7M6wtXBZbPL/GdfX0zW4bYKSh3KLakdXnDBDxvCrM+
         0RUA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=KI0C2HNR;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:1004:224b::b9 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1716571817; x=1717176617; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=86BOCwd7DdwJ4EePkPDoIjsZMVuT4FMoK/qXuNA4abg=;
        b=YOQXbOFJohlrWUSTA8W0w2koUy8/UzkCWAGTFeNWC5KEqhxVswWjJgfNK879tgkQMZ
         e3WSvNTW/XpOVyXeOAEjKgMKYamgpHS17Coj2Ryce8isVJDVkvlrxpFW960c2/T/E3Un
         PFlkMOuoi7GfMvWQg/WSJYBqxvUW1PBgKsg/Xp3y6pMKkzon9pqpg5UYEnbtQ6MR4uei
         A6JX9jX0+YbZxbEVzk53HVf8M5VmRzZ6gsL0xEtpWUU7ae3jNbM576kySd+P3KEQA/08
         iVMhmxpf2OhZmqvSxLF4I/oAKASbKKmE5BNVAbP+KEO3kVwPf5G5n4aSBt/ruv/A5YmB
         FhqQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1716571817; x=1717176617;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=86BOCwd7DdwJ4EePkPDoIjsZMVuT4FMoK/qXuNA4abg=;
        b=lYL7s9obABucvLOG4ne1kvgqMA6m842qVPMLfMEmMNZUH36yk5b9R0t4qeHz9BRgti
         dxZXCRxL5ej/tta8kWgmA0vXL9PN3t0NA/V2fUX+kTkg2iZ23Xr/HKG7+ljlsGPMjrKJ
         2kyXeAmD9rlMk6MbqTr6ZM0Oo9Z7wdTmGN2+Je8xE+1xoyfymUKMBhhVsS0IcWmtzV+Y
         vYtO5UcbPLnwAj/YoTEFNlJFZu4Xv+QVXa7g+YaMr4xdJWdsGwVq0AqF3yWB/5DjOaR6
         3rsVUtO9OvMSbSMgIdqqsmxu27O05gaxPikl9pPCGRScQh+vk1lEWL9aqkdbVPE/sywl
         bOAQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWwMjdQ9Z+uDNEHsmAKSeq9vvnjdJvMzN3uLnPLJvUTYIJ2zw3ge/aNGAh8cO2rBrUTT3ton7EsvElA+rthUblSaIvXnnoidg==
X-Gm-Message-State: AOJu0YySjQz+ypB45M9ZB/cfBeW5QO6/VENxoQ+Crs760kxu6ofm+354
	i2VycY8SBkcXSKpqQEFzgUdJnuMt+Q7sOr0YZcdjbaaJzByaILEf
X-Google-Smtp-Source: AGHT+IE61j8R2tY7E/90aW5ZCtYjAemoRSwn5W6KxXACwYbMlEs10jMk1+Q1MFw5cxOSxEsFvGGKEQ==
X-Received: by 2002:a5d:5142:0:b0:34c:f87b:f9fb with SMTP id ffacd0b85a97d-354f757d9c3mr5174424f8f.25.1716571816499;
        Fri, 24 May 2024 10:30:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:4ed2:b0:420:1552:a792 with SMTP id
 5b1f17b1804b1-42100e27958ls8300715e9.0.-pod-prod-00-eu-canary; Fri, 24 May
 2024 10:30:14 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXS26cKtdfxHSWYgF3gp7jcVaCzNKKNKPdYwIV+88E95+gfFXi4LTqm0gNJt5TI1i7k2F8n8yqIbsavL2x/OSZFfrc+8co4rnoaEQ==
X-Received: by 2002:adf:f88e:0:b0:354:c81e:b7ba with SMTP id ffacd0b85a97d-354f74ff98dmr5157813f8f.3.1716571814262;
        Fri, 24 May 2024 10:30:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1716571814; cv=none;
        d=google.com; s=arc-20160816;
        b=BlAWjaalc85thbO75j7tsyXiPLtf9GGQoHRpnIFySpsmuRr5ulI79ROO5YeibPQtU3
         KxeutXqdR9b2xCRHcirQJJJIWUP8hXrXiD7/+kqP8CzIPtdbFQTIw6lcAPoLW9F9H//r
         VY0jaw9bK1sU66AyB218VtaJfODJNX7rD8w/s4DRkAmWXBRIegpg9WMK4z94eurI7kP2
         TUNo5TdvibUqedcOHu7uFqxpPW/bV+sAFTHAXBTY/rsoZYIArK1gr1ouxZsfwExG8pmF
         COiBqrOA+QYCGPP2ARcentfjOl26IJj6iQ1Oxj6JyD6fFg26MNBSFBCXNijY5ShMrc9i
         LkLg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=B4Nq0eB//d4i3EFi6pEowHgt0pasM4PkRAR32O+xErA=;
        fh=M7gvNZ4KURGL+8P9bAAvMgLVYIm0bJHmEmSszCeVvBw=;
        b=j3Uqm86pNOzgr1IJaGR81jUSmcM0pICJu8pBKatOr4tLlvyFnzhg/U6vvHK74xtO8v
         A6+iy0j+1WvRLc/ZVJOqPf9VHmGDBlue8W7/ydQMtrQELZDceKKCtxhs53aMyCKYDDuQ
         DY9ajnhLUnmC8sqpIcax6YYqXwWruUe44chIlWSib1CAlb6nl85ufmMeYsaDRA00Vz1v
         QBSL1Jf2NRVnLuIQUSMlyFQAw/tINzwB316E8qfkNMH+UCjOrIGewI1Yw+JcPSsJQZBD
         sRT8jYvSNqfMhZ5PETZkBW/Bqg/YqpJVtJkLGJDuqmATgLruYBCbwZ4jAv7VUk4CZaI6
         3OJg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=KI0C2HNR;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:1004:224b::b9 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-185.mta0.migadu.com (out-185.mta0.migadu.com. [2001:41d0:1004:224b::b9])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-42100fa62b1si966735e9.1.2024.05.24.10.30.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 24 May 2024 10:30:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:1004:224b::b9 as permitted sender) client-ip=2001:41d0:1004:224b::b9;
X-Envelope-To: mathieu.desnoyers@efficios.com
X-Envelope-To: bfoster@redhat.com
X-Envelope-To: keescook@chromium.org
X-Envelope-To: linux-kernel@vger.kernel.org
X-Envelope-To: linux-bcachefs@vger.kernel.org
X-Envelope-To: glider@google.com
X-Envelope-To: elver@google.com
X-Envelope-To: dvyukov@google.com
X-Envelope-To: kasan-dev@googlegroups.com
X-Envelope-To: nathan@kernel.org
X-Envelope-To: ndesaulniers@google.com
X-Envelope-To: morbo@google.com
X-Envelope-To: justinstitt@google.com
X-Envelope-To: llvm@lists.linux.dev
Date: Fri, 24 May 2024 13:30:09 -0400
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
Cc: Brian Foster <bfoster@redhat.com>, Kees Cook <keescook@chromium.org>, 
	linux-kernel <linux-kernel@vger.kernel.org>, linux-bcachefs@vger.kernel.org, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	Nathan Chancellor <nathan@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Bill Wendling <morbo@google.com>, Justin Stitt <justinstitt@google.com>, llvm@lists.linux.dev
Subject: Re: Use of zero-length arrays in bcachefs structures inner fields
Message-ID: <jqj6do7lodrrvpjmk6vlhasdigs23jkyvznniudhebcizstsn7@6cetkluh4ehl>
References: <986294ee-8bb1-4bf4-9f23-2bc25dbad561@efficios.com>
 <vu7w6if47tv3kwnbbbsdchu3wpsbkqlvlkvewtvjx5hkq57fya@rgl6bp33eizt>
 <944d79b5-177d-43ea-a130-25bd62fc787f@efficios.com>
 <7236a148-c513-4053-9778-0bce6657e358@efficios.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <7236a148-c513-4053-9778-0bce6657e358@efficios.com>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=KI0C2HNR;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates
 2001:41d0:1004:224b::b9 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

On Fri, May 24, 2024 at 12:04:11PM -0400, Mathieu Desnoyers wrote:
> On 2024-05-24 11:35, Mathieu Desnoyers wrote:
> > [ Adding clang/llvm and KMSAN maintainers/reviewers in CC. ]
> >=20
> > On 2024-05-24 11:28, Kent Overstreet wrote:
> > > On Thu, May 23, 2024 at 01:53:42PM -0400, Mathieu Desnoyers wrote:
> > > > Hi Kent,
> > > >=20
> > > > Looking around in the bcachefs code for possible causes of this KMS=
AN
> > > > bug report:
> > > >=20
> > > > https://lore.kernel.org/lkml/000000000000fd5e7006191f78dc@google.co=
m/
> > > >=20
> > > > I notice the following pattern in the bcachefs structures: zero-len=
gth
> > > > arrays members are inserted in structures (not always at the end),
> > > > seemingly to achieve a result similar to what could be done with a
> > > > union:
> > > >=20
> > > > fs/bcachefs/bcachefs_format.h:
> > > >=20
> > > > struct bkey_packed {
> > > > =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 __u64=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 _data[0];
> > > >=20
> > > > =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 /* Size of combine=
d key and value, in u64s */
> > > > =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 __u8=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 u64s;
> > > > [...]
> > > > };
> > > >=20
> > > > likewise:
> > > >=20
> > > > struct bkey_i {
> > > > =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 __u64=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 _data[0];
> > > >=20
> > > > =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 struct bkey=C2=A0=
=C2=A0=C2=A0=C2=A0 k;
> > > > =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 struct bch_val=C2=
=A0 v;
> > > > };
> > > >=20
> > > > (and there are many more examples of this pattern in bcachefs)
> > > >=20
> > > > AFAIK, the C11 standard states that array declarator constant expre=
ssion
> > > >=20
> > > > Effectively, we can verify that this code triggers an undefined beh=
avior
> > > > with:
> > > >=20
> > > > #include <stdio.h>
> > > >=20
> > > > struct z {
> > > > =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 int x[0];
> > > > =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 int y;
> > > > =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 int z;
> > > > } __attribute__((packed));
> > > >=20
> > > > int main(void)
> > > > {
> > > > =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 struct z a;
> > > >=20
> > > > =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 a.y =3D 1;
> > > > =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 printf("%d\n", a.x=
[0]);
> > > > }
> > > > delimited by [ ] shall have a value greater than zero.
> > >=20
> > > Yet another example of the C people going absolutely nutty with
> > > everything being undefined. Look, this isn't ok, we need to get work
> > > done, and I've already wasted entirely too much time on ZLA vs. flex
> > > array member nonsense.
> > >=20
> > > There's a bunch of legit uses for zero length arrays, and your exampl=
e,
> > > where we're not even _assigning_ to x, is just batshit. Someone needs=
 to
> > > get his head examined.
>=20
> Notice how a.y is first set to 1, then a.x[0] is loaded, expecting to
> alias with a.y.
>=20
> This is the same aliasing pattern found in bcachefs, for instance here:
>=20
> bcachefs_format.h:
>=20
> struct jset {
> [...]
>         __u8                    encrypted_start[0];
>=20
>         __le16                  _read_clock; /* no longer used */
>         __le16                  _write_clock;
>=20
>         /* Sequence number of oldest dirty journal entry */
>         __le64                  last_seq;
>=20
>=20
>         struct jset_entry       start[0];
>         __u64                   _data[];
> } __packed __aligned(8);
>=20
> where struct jset last_seq field is set by jset_validate():
>=20
> 		jset->last_seq =3D jset->seq;
>=20
> and where journal_read_bucket() uses the encrypted_start member as input:
>=20
>                 ret =3D bch2_encrypt(c, JSET_CSUM_TYPE(j), journal_nonce(=
j),
>                              j->encrypted_start,
>                              vstruct_end(j) - (void *) j->encrypted_start=
);

Except we're just using it as a marker for an offset into the struct,
the same "aliasing" issue would apply if we were just using offsetof()
to calculate the offsets directly.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/jqj6do7lodrrvpjmk6vlhasdigs23jkyvznniudhebcizstsn7%406cetkluh4ehl=
.
