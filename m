Return-Path: <kasan-dev+bncBC24VNFHTMIBBFFZ5D5AKGQEXBXOUFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id A4E5F26460F
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Sep 2020 14:31:17 +0200 (CEST)
Received: by mail-qt1-x83d.google.com with SMTP id g1sf3967460qtc.22
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Sep 2020 05:31:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599741076; cv=pass;
        d=google.com; s=arc-20160816;
        b=uls/RXRVAHk3U2Q1Hxsa2aVdPLeIDW2+RS0g1raVIIdIQVRs7KISXLdNgEnk5h7R9e
         gNkk2VrRbxeohi28zngxINE2BdOpYysiDYT7jtwDI6Vt0kz9krWE+f1Ca9gsdraPPMqP
         toQe7+Mfwz8/SEDA72mN4Sa1mtrdlUVvF7Qr8lj8i8LPBLWStPBqOa0FjyC9n1jt13IH
         J0wnfVghLmG0Usn5bLMRDSfdKoslfjMnNn1z6voB0KGLxIU/9l7jQE/WQnC72BcgCsgp
         ThPjqdPDs3TIzkA4Pop6BY3OTivV4nBBDQnxUoG1wdd43b7hDyVUUvEGdD72wv7XbJ7E
         vL/Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=3Am3HptuSdMrN3xn+JQ8w3xebS2fueSBRcqdMwgCTAc=;
        b=VKte7EIbUygNcOX8cdEmz91fuQ7PI7DdIhC6p6Pocyu3xhwe+sZPf8RRmwJLw6RsD/
         pZYNjAoFFwkVBv2TFrXfFAeNSsF/3MMSt4lEMTqHvLaKpJZ1KHnLUWiJBgwJhynIjSmT
         95NF9dvv8fHu01B0Xcjigsw9eT6mWMrgJGnKHJZ2B0TWILMINXNf08umY6ljDQFBQj1P
         8fzL1WIYchBdDz+6VNeU90U/30q4q0R+e4f3XqiSZC4wr7mhEGjymnHprnk7xJHdXU1n
         DBB7cB7/ef9z/rfuoj5je72QwqucFUGu+x72dMvGVKWxGarjY2OHH1ffQu336pbyO02f
         NsVw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=iyom=ct=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=iyOM=CT=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=3Am3HptuSdMrN3xn+JQ8w3xebS2fueSBRcqdMwgCTAc=;
        b=rGTRhMctwR1mX7Y8O5TDDe5J7QS+LbxfUAKJtVifp1lNc/P4bvDL8KHxJ2TArKYhU4
         z7CRC3iD80NqWLomkZH03IL2JvbarInK+3PgPWjyNvxwMLbcW+c7D29zuLmgbBDPoUqA
         3KYvv9BHz1H96A5NwxMgavYmurrpuNSMycDMB+LYnXCqaWQNHJm0kww19wK2wBivtHUv
         X2svPp+BpEqri38l3kbZLhaGnvVNu0YEI/e1eWSxUhAmELIzGMXUJ/cH3d5wPnDnW466
         U6TmUboy7bfgPNXhsE7HjqpdbBP/hUq5bdGSVy1WsaGr2dePm52wc4WzZAjOoweZ4Vtc
         qg9g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=3Am3HptuSdMrN3xn+JQ8w3xebS2fueSBRcqdMwgCTAc=;
        b=FIj8NA+s/bY06uTyWjz0DSWaVeBPBHASyKft5okgP5A2rT4A8bP9IkflvVo9HAPgHs
         uc029YVoWu14NUF1i54Eaeb3sKsmsw2Dg9UqbC11jYeslHDRbrbyoc/w5T6V9DVb7l/D
         4fbbaeWgwQlmwQgNsfYYSKfqZucXa6/qOmT30XukOtyJa1a3PC+iyLjCzfvcaent90yX
         X76mJOGMIKDghOBLWSuOWB57gVHKkxkPiN1WRDJwGOuh+OWIGEOt5zq6HxFqHRxiB80X
         GD02R3ur/ZEJCidIdjvDGjbt+8DUKuR7I4LvTvzJBR5R381cWA4NndMlENLLjWE4+W5V
         4kPA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530tkZAnRe2dvigfHxW/84jNsGq7ZFC41V5fEKPivLteE7ftm5HR
	YbaScI6WjdQ42hUhdIdHXOs=
X-Google-Smtp-Source: ABdhPJyrY3e46G3X298xnigZ7N6K/Jd93AEOgHCYgM12b7X71TCtshKsszPEMdCf1mX0M9Ifzr1Mkg==
X-Received: by 2002:a37:794:: with SMTP id 142mr7681795qkh.114.1599741076688;
        Thu, 10 Sep 2020 05:31:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:4ce:: with SMTP id 197ls2959681qke.1.gmail; Thu, 10 Sep
 2020 05:31:16 -0700 (PDT)
X-Received: by 2002:a05:620a:101a:: with SMTP id z26mr7606610qkj.300.1599741076279;
        Thu, 10 Sep 2020 05:31:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599741076; cv=none;
        d=google.com; s=arc-20160816;
        b=nod5lrCHogq3j8Oly/oDyWjuD+s3R3+JkdnfdASV4Zovl4PPNkwH5Ir3s7fhScm31P
         czpoU86VcOw7rj/p9b8qJbnQuwagvr9m37eo7+XYSi+U27zCIb6KquE2ZAWftiCdC5KM
         WylTrEvYzfDmLSCqIjbBDc0+HYRF8L46TpqHnF+1Jf2YWqzXviQcWZjY1P1PrLw8hxKM
         AQC8UmpFMMOLwNdifj/hq+MQqdy//kwywxXb7fwJpLe6bCAtrO1cNoEGBqRAXLxlR+K/
         FzRnJBFadC8X605u7z3hFo/TBDp+EdQ0gjbijGeFoSfjqDJZj1E0OGo4CJdwY02Y96HL
         aidA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=oGsxiJseZHscCn+5+b6Xb/PRZZCnjHpND5Y0WvVSFN8=;
        b=HlvsRlLF5IoeAF0s2gSRKGcFelBD8CWqNF8u06yMcXT/0s6EvZp+9FNZlZy71N0xbY
         PSvucLVEamMJH4tCFKoR0gz/HEVsJlJgF60RT9lBE/ksNJO1vwSQvo0knIh/srNOjMDd
         6VMDQZkBwSSxzGlS7Nr7e6Wk36X5LXSl9MTM4oalbzEtruhHF5vSZeCgg3R7YRV7DW5z
         JsLnKzWDJs5CpWRgM7UJ4iWJItvhfvgnWUry3jZg3mO65N/RumiPWSzqTq5dsbQMl/WG
         l5eNrk1LbMg3+kk/tJ36/VIFP/uljr7F1XbPFzQY4u1Xd3o12rpO61Z7m+VQ1qSWlSbz
         eM8A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=iyom=ct=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=iyOM=CT=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id z6si339748qkj.6.2020.09.10.05.31.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 10 Sep 2020 05:31:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=iyom=ct=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 209219] KSHAKER: scheduling/execution timing perturbations
Date: Thu, 10 Sep 2020 12:31:14 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: enhancement
X-Bugzilla-Who: elver@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-209219-199747-fMTJed1YNH@https.bugzilla.kernel.org/>
In-Reply-To: <bug-209219-199747@https.bugzilla.kernel.org/>
References: <bug-209219-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=iyom=ct=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=iyOM=CT=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

https://bugzilla.kernel.org/show_bug.cgi?id=209219

--- Comment #6 from Marco Elver (elver@google.com) ---
> Could these UAFs be detected by KCSAN?

KCSAN already instruments kfree() and will detect races between usage and
kfree(). But we know that KASAN is still the better tool to detect UAFs, due to
quarantine etc.

> Maybe we could bundle the two, as KCSAN already instruments the code?

KCSAN instruments memory accesses, and I think that's overkill/too
fine-grained.

From what I gather, we want to insert delays into strategic locations, such as
synchronization or special functions, to enumerate interesting schedules. This
will require (as suggested by Dmitry) a cooperative approach, inserting delay
functions either directly or via means of kprobes etc.

The other requirement seems to be, that we want something that could be applied
to all sanitizers, not just KCSAN.


On a whole, one direction I'm being reminded of is stateless model checking,
which can be applied to real code to perturb schedules in a systematic way. One
popular paper I'm aware of is the CHESS paper:
https://www.microsoft.com/en-us/research/wp-content/uploads/2016/02/pldi08-FairStatelessModelChecking.pdf

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-209219-199747-fMTJed1YNH%40https.bugzilla.kernel.org/.
