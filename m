Return-Path: <kasan-dev+bncBDQ27FVWWUFRBQ5CRHZQKGQEMTDMDSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc3f.google.com (mail-yw1-xc3f.google.com [IPv6:2607:f8b0:4864:20::c3f])
	by mail.lfdr.de (Postfix) with ESMTPS id A962517BED6
	for <lists+kasan-dev@lfdr.de>; Fri,  6 Mar 2020 14:33:56 +0100 (CET)
Received: by mail-yw1-xc3f.google.com with SMTP id u140sf3253367ywf.13
        for <lists+kasan-dev@lfdr.de>; Fri, 06 Mar 2020 05:33:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1583501635; cv=pass;
        d=google.com; s=arc-20160816;
        b=BrNlVCbcYQn/ObIZPq4FnUwn/xkfQhvNyyT4BpA1hwurBhjlvLGiVSD8aTyRCDmcDf
         EZgDZtcq0vwN3hmBhNunnpQU26AvmYJwwMhfCFepUKOgygRBzjB6gdjBODHh3y/eDP8C
         9YTJZdZJ5gultcwA6El1vwPghlgh3a6NByosoxRTxTxdJsP+1RAtqS8/zDLbhvDv7vYu
         0HmCiKmyKt9mkcLiQLcqroxnwGmIXzJXcFYCM4tBbmMj/IdOJqM7PkTcL1myU2qTec98
         XurkR+8ta5/3JXTzgbQyEqKKLckEpOIYMVezUnWGVfjKwabreTW2TIjbTHMfFlmpBtbH
         274Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=1UU44rrBCRLnpZZaehTAz1Kahg6RftoF2ynQ/8s0E3s=;
        b=NPNSRj7MvjSKOwKyZNra9OGecl6ViWCauTSSUKepysdU0Pwt9J63SBtitX+b7fSVG2
         3/ro16te0oKHJUPIZnNzQpEQ2EJvxm2Fd6N99AXpBQWzsWHtYBINKsJh1+weJoOfjC6M
         ho9LicSRvzpoIk43kIdffN/++bn2u8w6Ym5CcpJeVBH8KHk5zr5j+h9V2xojXiuTT2Fw
         4gph9rj/OJgs0n27SNr52IU8A0Uh30/ZMRXCqJ7/fBFJkSWQ8YZveWi2iG3OvWWUp05f
         oIimfUvq4Ae6gplbXLut9E2PCoNtCXAFcHPrXJOuz+B/9cFI64JNrXcjgPhha5zue+jD
         dmnA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b="rEoA/mjy";
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1UU44rrBCRLnpZZaehTAz1Kahg6RftoF2ynQ/8s0E3s=;
        b=fkb4faai3XI8QvWQiuwby8LHo26j7zmMorIUNW5MXQmGYsQkrU2YSQ8wOj20i/gtvA
         UD4hBzF7/r1HSyeuNrcZ4dzQprq+Mbnnv9wlkVu5SHEWY8gx6GTUMoVKJj4HQMupRJ4v
         1U0v3Ni0cIM8+rf5JZjw9tWEek8zur+FoeV6O84NJ8iwt0NYUe0GlRBXfK8qRg3vRLoV
         0oXLKLBZwGJyVw4ez+iP1dgEz0wI1N26JdBkQmYKP3/AT/3rx+9e5iZu9gmAfuVUYBi7
         xlJX8SeW8GjbcenebpL2lw/SfdRDDi2hdru8ELs8b988V88cDJiNYQ55njeYxpUbrzGt
         FqwA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=1UU44rrBCRLnpZZaehTAz1Kahg6RftoF2ynQ/8s0E3s=;
        b=oKI/VEfVCFf7AIlj6cH9SkpUnK3exm0PSfDZwL1qzPRmEgPNwnPpo8FmjSrJpxfm/Y
         sQch11sGnEoFVRCWFzMI/LChhDXRiSPmyWo5a8LJ7bijA4KGiw2NEQD7e9A2T1Pl/5Qt
         2wGhEDSr8/pPr7SxxXKgblGQtiLLCg8KAoEi6YUOh1afp4wHvDikStcNwjn1t/zzPnot
         2FJwAwX0Slfbk3vQbtgcLmPpOdFxwPiKs34lWVseB7p93rmqcAZBwpa7eBEWdvWZnGC6
         m5aIbnIjuxH2oBslB0rpGBAmu/1nEJS40P6NT6WOvgFbE+p1wkhXxGQqIHwUn3c1f30Q
         9Xkw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ1UNJ1gxncOyqTQx6pj1QklJJg6h1+eXxZHvFU5hDuYXZESHQ1L
	+opuyF9WcNmfr5J+veWPKWY=
X-Google-Smtp-Source: ADFU+vtbUs4iEOHqEQ+Vf6FklUCTk+S0wHJl690zxf3zITtjmCRxMNeZB8GB3wd9eIeBkkDnxEbfEA==
X-Received: by 2002:a81:6c82:: with SMTP id h124mr4197121ywc.258.1583501635613;
        Fri, 06 Mar 2020 05:33:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:8644:: with SMTP id w65ls433451ywf.3.gmail; Fri, 06 Mar
 2020 05:33:54 -0800 (PST)
X-Received: by 2002:a0d:d9cf:: with SMTP id b198mr4302654ywe.184.1583501634555;
        Fri, 06 Mar 2020 05:33:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1583501634; cv=none;
        d=google.com; s=arc-20160816;
        b=GMIO8lzcqSY/SqmbRWJZ3yAgzYXJ+YznA8+x+pkABB45XCzsNmisdttH0b0xnJQgiR
         pRMHjKlEBaGicI9u4LAIEHTkyLbpyoaxQT3f7c1Wiy8d5q9PG7X8jNLZFXaGHlQGFbtH
         DbgWqfp/jkt7vH8CMgIOvpHyN4fnV5iTJU6UJHP7WjAdvuWvUiuVH6aItCLgaIWhBYyD
         QDoOJX68M96AXFcEtN++NnGq/TZaUdqwa8TC+Qmtho3M593g79H1In+VO0XCNVkMO/si
         R7aS5s7iTEWddCI/afBEbf17GzM7+ya4oJ7uA1LU5ixr6y0O8Ve1L0ilMZAcvoyQwHe4
         YhRw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=gUiajEtqHykUipUDAxZZ8PHMye5BZieG1YJoiSofP8Y=;
        b=snB83lHiHv/MEHKl2Kp1d/XRNEdSpsDe2dHYTeaQtbfQX2v2dHI+2mGG+qA7Pvq/Ay
         1smap4X6eKMjaFJvCd2WqWqqz/qvd25J7OXcvMBA/37iqTI8gb2ZuH7SHF/qNUdXNyyk
         cMdsiGW6a4cYx76cFjL4ZAYFYnXQbN8RrYg3k7vWeslXdfI6SPL7GhwyN/PqUaHTJGA8
         cxlz9krXBVjYrbAEav5h12lQxv/tKsnclhwgYMArrF0+6n6Fal+6OyZh9OAx75l6oY/n
         AN3kP9S1aUfK2aQykcyJBj92/I7PzjgBSDhhVjwjEKNfSJjj5wpYK7TXn+TJLSzs06u1
         gcIQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b="rEoA/mjy";
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x443.google.com (mail-pf1-x443.google.com. [2607:f8b0:4864:20::443])
        by gmr-mx.google.com with ESMTPS id y19si175916yby.1.2020.03.06.05.33.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 06 Mar 2020 05:33:54 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::443 as permitted sender) client-ip=2607:f8b0:4864:20::443;
Received: by mail-pf1-x443.google.com with SMTP id l184so1130728pfl.7
        for <kasan-dev@googlegroups.com>; Fri, 06 Mar 2020 05:33:54 -0800 (PST)
X-Received: by 2002:a63:d845:: with SMTP id k5mr3272785pgj.183.1583501633687;
        Fri, 06 Mar 2020 05:33:53 -0800 (PST)
Received: from localhost (2001-44b8-111e-5c00-b120-f113-a8cb-35fd.static.ipv6.internode.on.net. [2001:44b8:111e:5c00:b120:f113:a8cb:35fd])
        by smtp.gmail.com with ESMTPSA id w195sm33586804pfd.65.2020.03.06.05.33.51
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 06 Mar 2020 05:33:52 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	linuxppc-dev@lists.ozlabs.org,
	kasan-dev@googlegroups.com,
	christophe.leroy@c-s.fr,
	aneesh.kumar@linux.ibm.com,
	bsingharora@gmail.com
Cc: Daniel Axtens <dja@axtens.net>
Subject: [PATCH v8 0/4] KASAN for powerpc64 radix
Date: Sat,  7 Mar 2020 00:33:36 +1100
Message-Id: <20200306133340.9181-1-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b="rEoA/mjy";       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::443 as
 permitted sender) smtp.mailfrom=dja@axtens.net
Content-Type: text/plain; charset="UTF-8"
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

Building on the work of Christophe, Aneesh and Balbir, I've ported
KASAN to 64-bit Book3S kernels running on the Radix MMU.

This provides full inline instrumentation on radix, but does require
that you be able to specify the amount of physically contiguous memory
on the system at compile time. More details in patch 4.

One quirk that I've noticed is that detection of invalid accesses to
module globals are currently broken - everything is permitted. I'm
sure this used to work, but it doesn't atm and this is why: gcc puts
the ASAN init code in a section called '.init_array'. Powerpc64 module
loading code goes through and _renames_ any section beginning with
'.init' to begin with '_init' in order to avoid some complexities
around our 24-bit indirect jumps. This means it renames '.init_array'
to '_init_array', and the generic module loading code then fails to
recognise the section as a constructor and thus doesn't run it. This
hack dates back to 2003 and so I'm not going to try to unpick it in
this series. (I suspect this may have previously worked if the code
ended up in .ctors rather than .init_array but I don't keep my old
binaries around so I have no real way of checking.)

v8: Rejig patch 4 commit message, thanks Mikey.
    Various tweaks to patch 4: fix some potential hangs, clean up
    some code, fix a trivial bug, and also have another crack at
    correct stack-walking based on what other arches do. Some very
    minor tweaks, and a review from Christophe.

v7: Tweaks from Christophe, fix issues detected by snowpatch.

v6: Rebase on the latest changes in powerpc/merge. Minor tweaks
      to the documentation. Small tweaks to the header to work
      with the kasan_late_init() function that Christophe added
      for 32-bit kasan-vmalloc support.
    No functional change.

v5: ptdump support. More cleanups, tweaks and fixes, thanks
    Christophe. Details in patch 4.

    I have seen another stack walk splat, but I don't think it's
    related to the patch set, I think there's a bug somewhere else,
    probably in stack frame manipulation in the kernel or (more
    unlikely) in the compiler.

v4: More cleanups, split renaming out, clarify bits and bobs.
    Drop the stack walk disablement, that isn't needed. No other
    functional change.

v3: Reduce the overly ambitious scope of the MAX_PTRS change.
    Document more things, including around why some of the
    restrictions apply.
    Clean up the code more, thanks Christophe.

v2: The big change is the introduction of tree-wide(ish)
    MAX_PTRS_PER_{PTE,PMD,PUD} macros in preference to the previous
    approach, which was for the arch to override the page table array
    definitions with their own. (And I squashed the annoying
    intermittent crash!)

    Apart from that there's just a lot of cleanup. Christophe, I've
    addressed most of what you asked for and I will reply to your v1
    emails to clarify what remains unchanged.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200306133340.9181-1-dja%40axtens.net.
