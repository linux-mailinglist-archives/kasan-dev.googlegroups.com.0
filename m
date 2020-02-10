Return-Path: <kasan-dev+bncBCD3NZ4T2IKRB4MGQ3ZAKGQEL6CQO7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc38.google.com (mail-yw1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id 50BC3157F98
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Feb 2020 17:23:14 +0100 (CET)
Received: by mail-yw1-xc38.google.com with SMTP id j185sf6477557ywf.21
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Feb 2020 08:23:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581351793; cv=pass;
        d=google.com; s=arc-20160816;
        b=IIDcO9JnpGECQR8vblPVz26niDuDAWBvA2/lXOZVuLtrXYLywZOTeH75O8u2YMvnzh
         SXOWHj/2I+9HxYFRd95E8oTDD/vKBehLo4WOHTrRDwyBebxByxk+cgDRG5hdYTGsX/40
         /jwPxsD2DmW3boOQQKh9uxx6zhFSVauDiug7r6WwWqEZzvvpYR184kswwYi9fKNSUd5W
         KglT1qZMnuNzDaXoeszD+ng6ralSJ149CqOQseaVvBw9Vqbvd0rgWPh51ZvKZ7tom43p
         iUqRZt1DgMDe4swQVyEKj577+w028CE4zleIwx6p/hh7Z9owi8uabfMHo9futTv7vPrS
         +hpQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:date:cc:to:from:subject
         :message-id:sender:dkim-signature;
        bh=5Bdez1rxKw2ipUEQvtKWDlT4751ZRBeKEGLFjkCXFC0=;
        b=YqIh5VTkkMfwnz1uJNaJGRYEMy9Pxv8JDz7VuKJ/d8xp2z8kLxWPVkyj+LInZKLaBo
         wzF4gvjm60yJo53bWQ7IOXcoZHUJKDZSY7fdtfnL2f4UdNUyLOYl4WCJpp1/Sk4j6PRm
         OZ31kH5ftvUA/5VOYmDPQXbPaehJBJAt/B5n8JJGu2/lxl/LWlySdnh4iNnkf36RRTWK
         31WFGq5sQeOYiZ1/drbr+Eo8bj7W+kUr4ZwegtFPo+dNYE64wh0+y09ri6jb7qJOQBd2
         8fqIg3Hro+LCSDtWojdWQBXMcjSu5aqeWO+efKzX0eCnJoTgNgEohlL7ptkeeh1OH4/O
         kbqw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=ot9S+A+S;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=5Bdez1rxKw2ipUEQvtKWDlT4751ZRBeKEGLFjkCXFC0=;
        b=ePin7CS6uylpPlR4AKtNb8hbvYupRLXH3N42xrt80qgQw2IWbGGU+r8K463UC4x1j3
         dkHqdVCIYyZsiJRgAd6UFMDtDdHEx9v+VN1Ja+Dq9/af0mssvuabpoTDoSlePvmKQHhp
         iX4FXeA1vTiAY22AeW0uA2icEqKjQGIkKkRCz7c51N/INktKd9W128dhkZgVJoUC7WJ2
         4sb9YPoSteCa/S+XjDQJrWlcASuX9y3HmgE83f83ZrcxIIwNmHG+tdRlcWOYn2E3scG3
         MKQwFvteydZFZEznFr687DWlrXm4MvqPazKnzdfKBDNk+Mph1yTrl9MbLtNTuW65vIPe
         cDTA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=5Bdez1rxKw2ipUEQvtKWDlT4751ZRBeKEGLFjkCXFC0=;
        b=lmFUSWHcHPhjyr5jgbUR/S7mnbMirTkbCd8mtwHMWR1GPsRiqQcXIwbsWbkE7vxWO7
         /udnNA2PIKy7aBD20t/yX2dOw/hOdca2ScZVVxNbd1mWsSY0TCmkmWEC2Eb4VFXaDo2C
         OUrUUSwNTfOkH4cLccnS5Lj1X49lL7RlXV6CrwlsoDbQGkN61vCq3NIDVYBnpiL6ppVf
         E4kvLYTuyueakqeoyntRI44IR5dZcn04JnwUzluuQJrY/RYqUrNz0KlGc080Rvu7+v3T
         0GVtffQDzVdmJSllR/71HfBbDDVLB3sY14j9oq9gQ/mKlqDvxS9C3hDCLMXwW86nN/be
         6g5w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXnYFtBx0whjxHRBxtHyC6bvaqeC+w3PfqVR7T/g7AAwDtATFJi
	qNXiukp2r+9Z4NM7/w3JXe0=
X-Google-Smtp-Source: APXvYqzHu7AnviUSuKuEv5j4e2yDWPpJ4EXJY+XcnQh4Y9SrqkFIkp0s7TGEWyVH/RCUSY0onYEZjg==
X-Received: by 2002:a0d:ea15:: with SMTP id t21mr1604010ywe.360.1581351793317;
        Mon, 10 Feb 2020 08:23:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:2ecc:: with SMTP id u195ls1360190ywu.11.gmail; Mon, 10
 Feb 2020 08:23:12 -0800 (PST)
X-Received: by 2002:a81:6084:: with SMTP id u126mr1724535ywb.115.1581351792906;
        Mon, 10 Feb 2020 08:23:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581351792; cv=none;
        d=google.com; s=arc-20160816;
        b=Cosoj0/GZ917T51SPcmT8TQPhM6ODggO0YBrR4+k7KTsmHcW6R8a8b66gh7tBOgF2E
         tp2OA9bYx40f0n1/yxLgLVyTQ/asLBuJ4ofIq9tlynCuSJfXI/kzNwJAm2nDaO/uD5cT
         Oo8N8R3WrYeCH2UPB9H09OHofLxhOuKxrEFb0l8L06oZQpGKlbX5ze8WKdDlK7ORQaBP
         utkNlT/LVLmR/vTEPLsjJYcgmY4nsA8GzOQI5bfu5ziC4BHBio9aYFMzWEq1IRT7aSvR
         /LZrzJDRmtfdoXSfnucWC7dQgGkFbXTXHOpg7/VM/Zl/3rDIn+sV2E+xEzjhO2eS4XXq
         E1FA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=TaHv+PKpHG2kLF+syKmgL65ROquUkDcK5zPG7XnFfj8=;
        b=jeN3CpOw2I03r8phGbrbWsz5jKV8BhGUiGthUVOBHV/6YiHC4n7S+AAkZfvqnHXIOr
         2oO9DHk1Qc1muJ6NVFXbbUUIgMvn8Ne2BIDjn6h52LUwCmagR0NwjkvqQXTrw4vAx8YP
         QQpsTkEcaL2LkvSWxVUVqkjCVdCXWNlsuqIjOp+jZezZOTdHFkiGNsLnD229Jq1q4de3
         uTSFEywNPENkHj1RCJjF3adU7kJrwSc0/8XZfleX6ZovD2eyIbjnZWI93+wZ23llKsbj
         1PWw4Q7oGvdNglCY278IOHpgZpSzNlvzklNaJjeeqx6QbB10zzszDyucMBeiaBhmQnwP
         mgxA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=ot9S+A+S;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qk1-x741.google.com (mail-qk1-x741.google.com. [2607:f8b0:4864:20::741])
        by gmr-mx.google.com with ESMTPS id i200si61466ywa.3.2020.02.10.08.23.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 10 Feb 2020 08:23:12 -0800 (PST)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::741 as permitted sender) client-ip=2607:f8b0:4864:20::741;
Received: by mail-qk1-x741.google.com with SMTP id v2so2142801qkj.2
        for <kasan-dev@googlegroups.com>; Mon, 10 Feb 2020 08:23:12 -0800 (PST)
X-Received: by 2002:ae9:e306:: with SMTP id v6mr2094560qkf.162.1581351792284;
        Mon, 10 Feb 2020 08:23:12 -0800 (PST)
Received: from dhcp-41-57.bos.redhat.com (nat-pool-bos-t.redhat.com. [66.187.233.206])
        by smtp.gmail.com with ESMTPSA id g6sm359335qki.100.2020.02.10.08.23.10
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 10 Feb 2020 08:23:11 -0800 (PST)
Message-ID: <1581351789.7365.32.camel@lca.pw>
Subject: Re: [PATCH] mm: fix a data race in put_page()
From: Qian Cai <cai@lca.pw>
To: Marco Elver <elver@google.com>, John Hubbard <jhubbard@nvidia.com>
Cc: Jan Kara <jack@suse.cz>, David Hildenbrand <david@redhat.com>, Andrew
 Morton <akpm@linux-foundation.org>, ira.weiny@intel.com, Dan Williams
 <dan.j.williams@intel.com>,  Linux Memory Management List
 <linux-mm@kvack.org>, Linux Kernel Mailing List
 <linux-kernel@vger.kernel.org>,  "Paul E. McKenney" <paulmck@kernel.org>,
 kasan-dev <kasan-dev@googlegroups.com>
Date: Mon, 10 Feb 2020 11:23:09 -0500
In-Reply-To: <CANpmjNNaHAnKCMLb+Njs3AhEoJT9O6-Yh63fcNcVTjBbNQiEPg@mail.gmail.com>
References: <5402183a-2372-b442-84d3-c28fb59fa7af@nvidia.com>
	 <8602A57D-B420-489C-89CC-23D096014C47@lca.pw>
	 <1a179bea-fd71-7b53-34c5-895986c24931@nvidia.com>
	 <CANpmjNNaHAnKCMLb+Njs3AhEoJT9O6-Yh63fcNcVTjBbNQiEPg@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.22.6 (3.22.6-10.el7)
Mime-Version: 1.0
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=ot9S+A+S;       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::741 as
 permitted sender) smtp.mailfrom=cai@lca.pw
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

On Mon, 2020-02-10 at 08:48 +0100, Marco Elver wrote:
> On Sun, 9 Feb 2020 at 08:15, John Hubbard <jhubbard@nvidia.com> wrote:
> >=20
> > On 2/8/20 7:10 PM, Qian Cai wrote:
> > >=20
> > >=20
> > > > On Feb 8, 2020, at 8:44 PM, John Hubbard <jhubbard@nvidia.com> wrot=
e:
> > > >=20
> > > > So it looks like we're probably stuck with having to annotate the c=
ode. Given
> > > > that, there is a balance between how many macros, and how much comm=
enting. For
> > > > example, if there is a single macro (data_race, for example), then =
we'll need to
> > > > add comments for the various cases, explaining which data_race situ=
ation is
> > > > happening.
> > >=20
> > > On the other hand, it is perfect fine of not commenting on each data_=
race() that most of times, people could run git blame to learn more details=
. Actually, no maintainers from various of subsystems asked for commenting =
so far.
> > >=20
> >=20
> > Well, maybe I'm looking at this wrong. I was thinking that one should a=
ttempt to
> > understand the code on the screen, and that's generally best--but here,=
 maybe
> > "data_race" is just something that means "tool cruft", really. So menta=
lly we
> > would move toward visually filtering out the data_race "key word".
>=20
> One thing to note is that 'data_race()' points out concurrency, and
> that somebody has deemed that the code won't break even with data
> races. Somebody trying to understand or modify the code should ensure
> this will still be the case. So, 'data_race()' isn't just tool cruft.
> It's documentation for something that really isn't obvious from the
> code alone.
>=20
> Whenever we see a READ_ONCE or other marked access it is obvious to
> the reader that there are concurrent accesses happening.  I'd argue
> that for intentional data races, we should convey similar information,
> to avoid breaking the code (of course KCSAN would tell you, but only
> after the change was done). Even moreso, since changes to code
> involving 'data_race()' will need re-verification that the data races
> are still safe.
>=20
> > I really don't like it but at least there is a significant benefit from=
 the tool
> > that probably makes it worth the visual noise.
> >=20
> > Blue sky thoughts for The Far Future: It would be nice if the tools got=
 a lot
> > better--maybe in the direction of C language extensions, even if only u=
sed in
> > this project at first.
>=20
> Still thinking about this.  What we want to convey is that, while
> there are races on the particular variable, nobody should be modifying
> the bits here. Adding a READ_ONCE (or data_race()) would miss a
> harmful race where somebody modifies these bits, so in principle I
> agree. However, I think the tool can't automatically tell (even if we
> had compiler extensions to give us the bits accessed) which bits we
> care about, because we might have something like:
>=20
> int foo_bar =3D READ_ONCE(flags) >> FOO_BAR_SHIFT;  // need the
> READ_ONCE because of FOO bits
> .. (foo_bar & FOO_MASK) ..  // FOO bits can be modified concurrently
> .. (foo_bar & BAR_MASK) ..  // nobody should modify BAR bits
> concurrently though !
>=20
> What we want is to assert that nobody touches a particular set of
> bits. KCSAN has recently gotten ASSERT_EXCLUSIVE_{WRITER,ACCESS}
> macros which help assert properties of concurrent code, where bugs
> won't manifest as data races. Along those lines, I can see the value
> in doing an exclusivity check on a bitmask of a variable.
>=20
> I don't know how much a READ_BITS macro could help, since it's
> probably less ergonomic to have to say something like:
>   READ_BITS(page->flags, ZONES_MASK << ZONES_PGSHIFT) >> ZONES_PGSHIFT.
>=20
> Here is an alternative:
>=20
> Let's say KCSAN gives you this:
>    /* ... Assert that the bits set in mask are not written
> concurrently; they may still be read concurrently.
>      The access that immediately follows is assumed to access those
> bits and safe w.r.t. data races.
>=20
>      For example, this may be used when certain bits of @flags may
> only be modified when holding the appropriate lock,
>      but other bits may still be modified locklessly.
>    ...
>   */
>    #define ASSERT_EXCLUSIVE_BITS(flags, mask)   ....
>=20
> Then we can write page_zonenum as follows:
>=20
> static inline enum zone_type page_zonenum(const struct page *page)
>  {
> +       ASSERT_EXCLUSIVE_BITS(page->flags, ZONES_MASK << ZONES_PGSHIFT);
>         return (page->flags >> ZONES_PGSHIFT) & ZONES_MASK;
>  }

Actually, it seems still need to write if I understand correctly,

ASSERT_EXCLUSIVE_BITS(page->flags, ZONES_MASK << ZONES_PGSHIFT);
return data_race((page->flags >> ZONES_PGSHIFT) & ZONES_MASK);

On the other hand, if you really worry about this thing could go wrong, it =
might
be better of using READ_ONCE() at the first place where it will be more fut=
ure-
proof with the trade-off it might generate less efficient code optimization=
?

Alternatively, is there a way to write this as this?

return ASSERT_EXCLUSIVE_BITS(page->flags, ZONES_MASK << ZONES_PGSHIFT);

Kind of ugly but it probably cleaner.

>=20
> This will accomplish the following:
> 1. The current code is not touched, and we do not have to verify that
> the change is correct without KCSAN.
> 2. We're not introducing a bunch of special macros to read bits in variou=
s ways.
> 3. KCSAN will assume that the access is safe, and no data race report
> is generated.
> 4. If somebody modifies ZONES bits concurrently, KCSAN will tell you
> about the race.
> 5. We're documenting the code.
>=20
> Anything I missed?
>=20
> Thanks,
> -- Marco
>=20
>=20
>=20
>=20
>=20
> > thanks,
> > --
> > John Hubbard
> > NVIDIA
> >=20
> > > >=20
> > > > That's still true, but to a lesser extent if more macros are added.=
 In this case,
> > > > I suspect that READ_BITS() makes the commenting easier and shorter.=
 So I'd tentatively
> > > > lead towards adding it, but what do others on the list think?
> > >=20
> > > Even read bits could be dangerous from data races and confusing at be=
st, so I am not really sure what the value of introducing this new macro. P=
eople who like to understand it correctly still need to read the commit log=
s.
> > >=20
> > > This flags->zonenum is such a special case that I don=E2=80=99t reall=
y see it regularly for the last few weeks digging KCSAN reports, so even if=
 it is worth adding READ_BITS(), there are more equally important macros ne=
ed to be added together to be useful initially. For example, HARMLESS_COUNT=
ERS(), READ_SINGLE_BIT(), READ_IMMUTATABLE_BITS() etc which Linus said exac=
tly wanted to avoid.
> > >=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/1581351789.7365.32.camel%40lca.pw.
