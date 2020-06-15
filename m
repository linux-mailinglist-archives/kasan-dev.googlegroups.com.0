Return-Path: <kasan-dev+bncBC7OBJGL2MHBB2OTTX3QKGQEN5X7ETA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93a.google.com (mail-ua1-x93a.google.com [IPv6:2607:f8b0:4864:20::93a])
	by mail.lfdr.de (Postfix) with ESMTPS id C97EE1F9686
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Jun 2020 14:30:34 +0200 (CEST)
Received: by mail-ua1-x93a.google.com with SMTP id a20sf5487639uao.19
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Jun 2020 05:30:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592224234; cv=pass;
        d=google.com; s=arc-20160816;
        b=hgwphLyYWhK09fPHHR9K+AA4wl+a1BYAbERb5XLSLCSStgH9EhL8OFMDKUhSXvnZlE
         4yca7s7g84UhOFeZu8tPz0m7pYU7ydu3NhoR3c5Ma56V8YYVWpACTGK6sr6FCJu0H960
         d+5zaM9EjBEO39K5kczQ43O1a77gIMaCAQsv23JFs0Hmcz3V3ukSkZNG0837d3v7qPw9
         AyQdIhN6unRY9KMqqyd1dEbq1Z99wMkJj/YGEzPmshQPX7fe+tSG7vTAdjycICG1aFtu
         aCbMW1/+lO7Z4V6iu2pKLbbX1+03LTNtHiG86F7xHvtVAlh8iySpCGlzmvWw/YdmKHVQ
         YqGg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=QbleZ0yy8TQbsfoAxJsw35phpxXV0UVkp9GFJ571w5U=;
        b=vqeFWTkDsjxl2stHDSNASBRQyJ4LneKBKq838ObaACaHNwEIjBdySK6nlO6UnKTCEB
         2mHTUdPHWhBd1/V3yCKEyhP7okZOHT2SWEyopd1jdhjammFRE0zvCtPgeCsjo8qIfIdz
         3uLUnn7WCfDVu+aKzl3EtMwdwoFijbdwx0jN/DnU5tTNdiaYbYRJ/TO+y5Sj4ofGl9sA
         28DYfwQblroQf43XcYnOL7Z4LOInE8G1bZKjF7z+DlOT9k5664FN7jarTvbqU+SgbWDz
         FOfVy6uqOK9m4TYJHL7L6IzQLB49/lVs+B+AExYakDPlYWN/FVqYLwYNoOOQQCZiX5jC
         DLqA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JPDq6iHl;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=QbleZ0yy8TQbsfoAxJsw35phpxXV0UVkp9GFJ571w5U=;
        b=bt0AxIoI1aZUmMwSC0YZs3O/7ouRrOesqayHIxf9fYAGqF5Jl/AS18WoIETThlCasN
         zk27RjjrPOvDJjpsR8GXOrCz33nYTvIN7vMZq5x9kKCWR6jc/WYokakEvrtcjj+46QET
         gG94CiVnvV2o+1AnLXV2Dn3hqq/yX+zDH2ERKi7Vc5ieSCP5qLSbXe2TQT7F2tTQ7w+p
         Cp6noJ768TKznTvrGTmhF2L9XYvg4sdTC7TGU6tq+kGson/Uhh3KKKo9uSnE2Wks72ey
         FAfiveMvx1c2MoD7mz9S2Knsap2Lxi50RWfeuOVDIiHs3yT82RhrDgq+CFe0crjTOFs+
         xYaw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=QbleZ0yy8TQbsfoAxJsw35phpxXV0UVkp9GFJ571w5U=;
        b=dbymt2sTvban6UMPwd9TBDkb42dk6PRUkc97Zx1j2Gh8JQnM0rnhnz61AFmQNIa+gT
         +zQJXE1z57CsmyVggSBgKKj9n05xRTcwoR8R5I3OByLVt7i5iTxZxkX9eOv1ieeuIlej
         aC7MIZdzNs7wyiTDNiBdxl3ihLt7SmRo7ocLrNxG6p8C6pKHGBZVHzwff5uahvY7QhkV
         r5muKKEfXvh9nviIJP8OjUBYFbVdOozulbWKfip0wMf6wPjmMwVobmkWE9/uHIwzXc0s
         pWGvrbyyHD+/y9ISYku3MHX7ds0ZZai5mSKf3U6EHrsaXMX2/XBGE5qoKcaCgaSfmmfB
         3bfw==
X-Gm-Message-State: AOAM5301ZJOEPKq6a7W5UP50J20JIuY57z02TUGtf1AvGGW05BRuFevz
	+11SQ5gvHwfhLfYPPSf2Mmo=
X-Google-Smtp-Source: ABdhPJyUGBR7dXsE8yP8knzwRy2+/5kx08Ae/2Wt59h6BLxBFk/uqsKAuL+389dd10g792cRWVNHPg==
X-Received: by 2002:a67:ecc4:: with SMTP id i4mr13012178vsp.228.1592224233806;
        Mon, 15 Jun 2020 05:30:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:1c01:: with SMTP id c1ls582593vkc.7.gmail; Mon, 15 Jun
 2020 05:30:33 -0700 (PDT)
X-Received: by 2002:a1f:6282:: with SMTP id w124mr18125674vkb.97.1592224233452;
        Mon, 15 Jun 2020 05:30:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592224233; cv=none;
        d=google.com; s=arc-20160816;
        b=Z4Ov0MK1k9nuWgLZZ9wVs2qa2LvDBM8C5lY8/MUGVNABn0UrxnFuTSmbJ/xxeY2CiV
         Q3Xche6yi3iV/m4mrfgYG6DsdwI3/6MrEsniWkofb/2fsAbe34xHQQ4Ae9Eebkd23fBj
         rG2s7t+2baXqMKIcf+P7eZ+rIx+ve6KwcQRr/KdYP+Mv982+CP3rStNKzQu0V773D7+7
         Ekd0fAfVMZ43cYIsI7+ELGF2dA1115F+lTCIGz/YxtZx37ZlMhAg1iyhgTS0GR5lgszX
         HQdiXqBBFoRkwhoABeAjCFm/X5Wj2EEPGjZsmVwY9m5nVUKF/KTw5LSFgSyiHNW39lDX
         T4Aw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=tWSA5FVA8bXyBwXd6vhDmVX7eTx9jTJK5LgJxK7Wee0=;
        b=RG7qq+J77Qww/Bj4BeaMIzyrFWDxg8z2gWD2I4XwKjmaYqqRRgJO2hMmNgriq/Hh6I
         99s2+yG/qtqNlg2zS5ELWFlzG7Us5giVO7OMWSyKVTOe9OBu9WhIod3pUz7P7VemTwFM
         I+YKE9oGPYN495aGDK1KnIdEHehAHZxMcgpkGtihseOPDplhncAY0vg5bdjHkssD4JW0
         PZGpa8fVEokfeD2wNKNkuGtUCL7kAPNrfTMcRhKn5LjcBokZs4mOCpMIxLACqqDWWVFL
         fU71a34aEq44gw7uJyL67Nh7mjOIs9kCcUVFKlrcjOXVwkGUuOU62gHg9kgjuJ70rghr
         gytw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JPDq6iHl;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x242.google.com (mail-oi1-x242.google.com. [2607:f8b0:4864:20::242])
        by gmr-mx.google.com with ESMTPS id o18si728300vke.0.2020.06.15.05.30.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 15 Jun 2020 05:30:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) client-ip=2607:f8b0:4864:20::242;
Received: by mail-oi1-x242.google.com with SMTP id k4so15715733oik.2
        for <kasan-dev@googlegroups.com>; Mon, 15 Jun 2020 05:30:33 -0700 (PDT)
X-Received: by 2002:a05:6808:34f:: with SMTP id j15mr8820767oie.121.1592224232767;
 Mon, 15 Jun 2020 05:30:32 -0700 (PDT)
MIME-Version: 1.0
References: <000001d5824d$c8b2a060$5a17e120$@codeaurora.org>
 <CACT4Y+aAicvQ1FYyOVbhJy62F4U6R_PXr+myNghFh8PZixfYLQ@mail.gmail.com>
 <CANpmjNOx7fuLLBasdEgnOCJepeufY4zo_FijsoSg0hfVgN7Ong@mail.gmail.com>
 <002801d58271$f5d01db0$e1705910$@codeaurora.org> <CANpmjNPVK00wsrpcVPFjudpqE-4-AVnZY0Pk-WMXTtqZTMXoOw@mail.gmail.com>
In-Reply-To: <CANpmjNPVK00wsrpcVPFjudpqE-4-AVnZY0Pk-WMXTtqZTMXoOw@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 15 Jun 2020 14:30:20 +0200
Message-ID: <CANpmjNM9RhZ_V7vPBLp146m_JRqajeHgRT3h3gSBz3OH4Ya_Yg@mail.gmail.com>
Subject: Re: KCSAN Support on ARM64 Kernel
To: sgrover@codeaurora.org
Cc: Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>, "Paul E. McKenney" <paulmck@linux.ibm.com>, 
	Andrea Parri <parri.andrea@gmail.com>, Alan Stern <stern@rowland.harvard.edu>, 
	Mark Rutland <mark.rutland@arm.com>, Will Deacon <will@kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=JPDq6iHl;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Mon, 14 Oct 2019 at 11:31, Marco Elver <elver@google.com> wrote:
> My plan was to send patches upstream within the month.
[...]
> On Mon, 14 Oct 2019 at 11:30, <sgrover@codeaurora.org> wrote:
[...]
> > When can we expect upstream of KCSAN on kernel mainline. Any timeline?
[...]
> > > > Can you please tell me if KCSAN is supported on ARM64 now? Can I ju=
st rebase the KCSAN branch on top of our let=E2=80=99s say android mainline=
 kernel, enable the config and run syzkaller on that for finding race condi=
tions?
[...]
> > KCSAN does not yet have ARM64 support. Once it's upstream, I would expe=
ct that Mark's patches (from repo linked in LKML thread) will just cleanly =
apply to enable ARM64 support.

Just FYI, KCSAN is in mainline now. I believe porting it to other
architectures has also become much simpler due to its reworked
ONCE/atomic support relying on proper compiler instrumentation instead
of other tricks.

Thanks,
-- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNM9RhZ_V7vPBLp146m_JRqajeHgRT3h3gSBz3OH4Ya_Yg%40mail.gmail.=
com.
