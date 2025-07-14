Return-Path: <kasan-dev+bncBDLNDJMHSEARB3HQ2LBQMGQEFSZ6S2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3a.google.com (mail-io1-xd3a.google.com [IPv6:2607:f8b0:4864:20::d3a])
	by mail.lfdr.de (Postfix) with ESMTPS id EBD0CB0387C
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Jul 2025 09:57:36 +0200 (CEST)
Received: by mail-io1-xd3a.google.com with SMTP id ca18e2360f4ac-873fd6e896bsf424415839f.3
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Jul 2025 00:57:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752479852; cv=pass;
        d=google.com; s=arc-20240605;
        b=O893/5HlfaWd8EpAwFFCinvVw0ha8r4eHdK7QCoC4NO49oiHpZBRxJNcS8+Kvmzk5y
         ssn13edoFQxHEqIG7bUUSF+X6J4ESp5eghfxIqY3lEN0ZG7Hp3FFGtgRPu+nswGkFDlI
         en5ln+AQx/jhC0+FtwDXkfF7KbfnkOjsa12JuU9qYxUID8JhOKfumfNydw1MCPkJ1dPY
         TktXDa1LzeXXORJv72VKck1ypN+y7k3jzEcckeUsjnCUpoIj9jBdxQdkqzpUQVD47uTO
         8c2RY+y1LIbAMNmPqBrnuB0G3Hu5rVqE7KbEUxdSUXBI5DzJBOTv48Gu2plAk3Sw08Dg
         p4cA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=q+AFl0ZjztPhevR2dQ74NmR+JZbnwsUzFbtWbR5uUp0=;
        fh=y3om/sc0ex6aY4Xa7K9z9ogNmgybnOQL0ztY0Z3HhGA=;
        b=XbFg5IwV+v9pS7XMd9US93X60j4qF764uqK9AS7+eDTSorIr2zUuxee4OOlKwKMKxs
         Pl5pefqkH95bOXMPmJEivSZ3rRSDhc4SzNc/nyprUnVAnLVtrJ29XOwqowPEQdC3wDCI
         mI2f8UYQMkMhrVTa85G1r4hmI+MvkAqxXYNwAGEeYw+ou1XvoHHQutV1vJx4XyNoNNW5
         2hzC5F3A3QrBIokEv4mMz8oAREBVXOk378E0x1De+Gxv+eX9/1Y5vC6pIg/qGK5Hz+Yv
         berSxwG4lg8XVeJS6iBw6FOwLXpAMOdqrZVVC99sfetfPjX+IBHNpSqIqzvMq+sSeibs
         ij6g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=E1e4lsss;
       spf=pass (google.com: domain of chris.bazley.wg14@gmail.com designates 2607:f8b0:4864:20::630 as permitted sender) smtp.mailfrom=chris.bazley.wg14@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752479852; x=1753084652; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=q+AFl0ZjztPhevR2dQ74NmR+JZbnwsUzFbtWbR5uUp0=;
        b=N89OF1GU7871b/vNLthpyiA2mg+79fbIluaL6dkjeVrbFzxRDc9y6eq18bntCNRLNr
         w+1uIIzJe/QWlvmAPTevMD58IZw581tD0lPJNkFT+fKYKB+voqv9/SfsPNwLxtOuKzBm
         zg4ZvbSmnDYoMK+w87mpD8l5CYMJ9X5PiD2xXDeq3XlL8wmZSW/eudHpd74lDDv9nzH/
         OZL8RenYLi43F8uqoYXhAPqhh0iv9GcDRvDKrjopj4/wGQC9C7a5slJPyOxCgs2yupF+
         oer3V39KIPG1YKmxKFMXKbpT3Ksno/KUEsl23gwJwF5R+d+GhrwASPXL3UXVBwyMQDVm
         5LnQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1752479852; x=1753084652; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=q+AFl0ZjztPhevR2dQ74NmR+JZbnwsUzFbtWbR5uUp0=;
        b=A3aRg3e3Co9LTWRk7ayyEwTWNCh6sjG3xmG9H+rtcqQ3fId+cVXQybgwPEiLoIS241
         39UpzBAJxCBa+dodYMUem4aQrWyvkqMoIL7LTRpCYeE3lJEXo4HgvXJEL9Np0DOM4H1c
         DA3GYt9L7OnhHFNJb9+pae8otKkM5axFdFkrmSrjOEQfNf6Dr2qPyR3JJI1vBVMwCv0d
         olh1m+yyECgRvhA9CShRKSG/0kB913thBSuowIAtI/+OijQKW+I9a5gyNCtvLdXs/Nlv
         Eae81qtp8xDE59SJfqQOywS8/GLc7eqhRIEp00VRQLbJk2yXldPWhkg9ATCHw/N6efA/
         jA8A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752479852; x=1753084652;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=q+AFl0ZjztPhevR2dQ74NmR+JZbnwsUzFbtWbR5uUp0=;
        b=XPZxPLhD+viDr3Ol/YPAS22nlDtfgcysMUP+sPzK/iM1ca0jWkYS4Ml6n3wJxoPcvO
         s+OI90RnJkr1Q6nHgqYrjD4tITXO1jrOeC4IaIa5HTXGHik5WaBWgxMH+FYC0d1dp+E3
         vFUNtzs4YQZTsVhTn86BQxO66yJHFUKkvbyNrxavFlc181CBdAg9gDLgTC+OkTyPkP2x
         V9OfmOmDjkxiGrpmoiVN/L6lrzdV0xFrbjeql5BfSjyTorITOT38THZrM16xwMl5ucEU
         pr6HZFIoMs/CH8232selNoc5bdvRo+7LfM/YzPv34a6/4/7gN8akO/A40zfeO5lB6rf/
         I1CA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV36pti73Lzcu3pQGur8VCYccaJfOun/eQwZCpD+3oSphppGM9wgKSmfOPo7H3nzi3iAgrDtw==@lfdr.de
X-Gm-Message-State: AOJu0YyDcAnkL/AHK7TEG/EK0a7e6tGPcbKXKIgILdU2g5edJBeDj2Cx
	2uO5fVMhCIQ+torsdf5NT4cHUhNj43bZ+tJwiSMVu6l0N7WNDyFXCw+d
X-Google-Smtp-Source: AGHT+IEkk2Hzepuba8FKg7cHbqbKcMQJNZ/iT/rbv78Yl6JvLLoTrIUgdLAMI95WCi19iQG/xJW70A==
X-Received: by 2002:a05:6e02:1fce:b0:3dd:d194:f72d with SMTP id e9e14a558f8ab-3e253287825mr136568255ab.8.1752479852341;
        Mon, 14 Jul 2025 00:57:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdxsCfUd0gnUGfGOjBPjWUq/vS+YwXIyWvBM2YNSiCdWg==
Received: by 2002:a05:6e02:481b:b0:3dd:b548:6cb2 with SMTP id
 e9e14a558f8ab-3e244105fc0ls34210085ab.1.-pod-prod-03-us; Mon, 14 Jul 2025
 00:57:31 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUr6ndlCB6Eq9ioE8KIEVWVv6BOISudP/UYSjZgatYLpwbr2nyA0iyzrGLRRLyd2n9PBCtdalycxgU=@googlegroups.com
X-Received: by 2002:a05:6e02:198b:b0:3dd:d33a:741a with SMTP id e9e14a558f8ab-3e253325ffbmr121804295ab.18.1752479851435;
        Mon, 14 Jul 2025 00:57:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752479851; cv=none;
        d=google.com; s=arc-20240605;
        b=Np84JWtseVfeJ5dOXeGSgTevv++c56dslH0V2mfcC3siQtnrhcj6UB7qo3x+vXAbKm
         dOU2rJqfWJeyrvomoYZybW7m1MufW5GHyiek7rJTPu56VXPFE+fgtA1sWwOWgoRqrjw2
         B1EDFTXQEHj6NSoESJj1/4FF6bbgpdyw93g3dQrQtCJJIjbK3qxo20ybTd3vNKqNhGjE
         P9ElCMiwOiZ+0Q8rK5B4iFj7huhlCoUkm5MRp/LTC7s34TOjPGytHLe+M7D/T1UCo2y+
         1KSxiBegjtW8H/DE9jbjrew3l4k6ZRrzU9lctGNp3xszqQlGJD6lRu/LAE5kH+NQixdM
         1EfA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=roSjWg6cHsmiMCH7MqmdlcAQ72VjQ3ISK0vUZNe2l3k=;
        fh=J0s6JNaaouaxJa0Eys0NlpwTiOdYk8XDIM1mWLMmjwU=;
        b=LaWZLJXjF/p+h4MulQES7mFibyv86HimXNl1b1ffkOigNflfWVQe1aEmDVjLnn2GDL
         PnqqQAyw4RxZpCwzI/iVWuxIWnwgAkKmFE9sXxLq1dD9HXY86tRJtoHXdAV1fOuBMqFI
         cizwpjd0KBlG7a+g75VqQGngwutVqVYacnYua8I4KmejTOYIyL0++CG49rWA1PBNwQpH
         lwK5Gmv4sl6TJm5yZ3w5yEaUAq0RAcx6QIfmZXRu6iLWOt4ppONe8+kTXD4a3AJpoFbp
         0i3/m98V7zRShdQ2nLB0FV4gg40Hmr04x2IazlA2Oj8dgAyNSROhP08wSBaR3kjGUGMH
         txbA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=E1e4lsss;
       spf=pass (google.com: domain of chris.bazley.wg14@gmail.com designates 2607:f8b0:4864:20::630 as permitted sender) smtp.mailfrom=chris.bazley.wg14@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x630.google.com (mail-pl1-x630.google.com. [2607:f8b0:4864:20::630])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-5055667f94csi337211173.2.2025.07.14.00.57.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Jul 2025 00:57:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of chris.bazley.wg14@gmail.com designates 2607:f8b0:4864:20::630 as permitted sender) client-ip=2607:f8b0:4864:20::630;
Received: by mail-pl1-x630.google.com with SMTP id d9443c01a7336-235e1d710d8so50920325ad.1
        for <kasan-dev@googlegroups.com>; Mon, 14 Jul 2025 00:57:31 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUXo+qwHz6yQocFTbtF0G0x/fn1+xiXZ90rp+M9oXBRrsAOiNm0AWSlklUw2YMOF2Pl4N41XTGj+V8=@googlegroups.com
X-Gm-Gg: ASbGncuy1qcYmyjmWCq9Pg2DfKbW0ErOIXczayYAd+6CRpU54GEZgYTaa6xmY5GgZYe
	28u9zsWIxtM4FLhJlswxLlqOxvnCF6Y7yHv6bK/SW+IeQBCoQXF79LWMfin3vyGp9PgofpHEb4k
	YrAlHYPzsm8ppcC4KUfQVZkH9leZkgiX7WZz+QBgUlUJao9RLnWZu+lv+4eKdlcffD3aDzxyWbV
	g9PnKEiw1228x0=
X-Received: by 2002:a17:902:f98f:b0:23c:7b9e:1638 with SMTP id
 d9443c01a7336-23dede8c409mr132835185ad.35.1752479850537; Mon, 14 Jul 2025
 00:57:30 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1751862634.git.alx@kernel.org> <033bf00f1fcf808245ae150346019aa7b997ea11.1751862634.git.alx@kernel.org>
 <CAHk-=wh9Pqz07ne9iSt1_v0c14rkOGvF9AbEkaq1KnFhQD1SSA@mail.gmail.com> <CAEHU8x9UKFWjuE2JPd99CS7wY-x_0kE0k=K3rfYUCJ29uzOSOA@mail.gmail.com>
In-Reply-To: <CAEHU8x9UKFWjuE2JPd99CS7wY-x_0kE0k=K3rfYUCJ29uzOSOA@mail.gmail.com>
From: Christopher Bazley <chris.bazley.wg14@gmail.com>
Date: Mon, 14 Jul 2025 08:57:17 +0100
X-Gm-Features: Ac12FXyCl2UVr3KuLV2X3zg5b49uXMIerI9JyvxvwFjPX5uWMA4vnuopNVK3Pd8
Message-ID: <CAEHU8x9+_9VdMCp2j20hQJFTmCfD9_R8yacGg67JeQYwo3KPww@mail.gmail.com>
Subject: Re: [RFC v3 3/7] mm: Use seprintf() instead of less ergonomic APIs
To: Linus Torvalds <torvalds@linux-foundation.org>
Cc: Alejandro Colomar <alx@kernel.org>, linux-mm@kvack.org, linux-hardening@vger.kernel.org, 
	Kees Cook <kees@kernel.org>, shadow <~hallyn/shadow@lists.sr.ht>, 
	linux-kernel@vger.kernel.org, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>, 
	Andrew Clayton <andrew@digital-domain.net>, Sven Schnelle <svens@linux.ibm.com>, 
	Heiko Carstens <hca@linux.ibm.com>, Tvrtko Ursulin <tvrtko.ursulin@igalia.com>, 
	"Huang, Ying" <ying.huang@intel.com>, Lee Schermerhorn <lee.schermerhorn@hp.com>, 
	Christophe JAILLET <christophe.jaillet@wanadoo.fr>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
	Chao Yu <chao.yu@oppo.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: chris.bazley.wg14@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=E1e4lsss;       spf=pass
 (google.com: domain of chris.bazley.wg14@gmail.com designates
 2607:f8b0:4864:20::630 as permitted sender) smtp.mailfrom=chris.bazley.wg14@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

On Sat, Jul 12, 2025 at 9:58=E2=80=AFPM Christopher Bazley
<chris.bazley.wg14@gmail.com> wrote:
>
> Hi Linus,
>
> On Mon, Jul 7, 2025 at 8:17=E2=80=AFPM Linus Torvalds
> <torvalds@linux-foundation.org> wrote:
> >
> > On Sun, 6 Jul 2025 at 22:06, Alejandro Colomar <alx@kernel.org> wrote:
> > >
> > > -       p +=3D snprintf(p, ID_STR_LENGTH - (p - name), "%07u", s->siz=
e);
> > > +       p =3D seprintf(p, e, "%07u", s->size);
> >
> > I am *really* not a fan of introducing yet another random non-standard
> > string function.
> >
> > This 'seprintf' thing really seems to be a completely made-up thing.
> > Let's not go there. It just adds more confusion - it may be a simpler
> > interface, but it's another cogniitive load thing, and honestly, that
> > "beginning and end" interface is not great.
> >
> > I think we'd be better off with real "character buffer" interfaces,
> > and they should be *named* that way, not be yet another "random
> > character added to the printf family".
>
> I was really interested to see this comment because I presented a
> design for a standard character buffer interface, "strb_t", to WG14 in
> summer of 2014.

Ugh, that should have been 2024. I'm getting old!

Chris

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AEHU8x9%2B_9VdMCp2j20hQJFTmCfD9_R8yacGg67JeQYwo3KPww%40mail.gmail.com.
