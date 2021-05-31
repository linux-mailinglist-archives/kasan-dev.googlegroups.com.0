Return-Path: <kasan-dev+bncBC7OBJGL2MHBBRW42KCQMGQEI63JU2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63c.google.com (mail-ej1-x63c.google.com [IPv6:2a00:1450:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id ABD1D395832
	for <lists+kasan-dev@lfdr.de>; Mon, 31 May 2021 11:37:10 +0200 (CEST)
Received: by mail-ej1-x63c.google.com with SMTP id q7-20020a1709063607b02903f57f85ac45sf336361ejb.15
        for <lists+kasan-dev@lfdr.de>; Mon, 31 May 2021 02:37:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1622453830; cv=pass;
        d=google.com; s=arc-20160816;
        b=gOX5VlzjbSbLB9dJidXhjNf5Z3msNKoMqHRPyBeOpdu9taQJ0Cp2zeaQCivUMOFU2m
         HLoMqA+KC5akZ300YvfqefbL/ljIUbQDu3WwJ8gykVHWey9mjIBHEZVF08ahUO40m8cU
         yQU2FUXzys11yXgnwnDEAmjbz6El6REOyQXFDmbEndmIKBNkzdUF1O/SPRUj2Md5Ncmj
         8dsWCNwJx2opt3jKr+Z9Dufy+C5udcAqQCSvUKkw+McQHfDplJl/Y1PZieQT6C+H+qr0
         wc4weRgn1PAiNbve2Pph0EEbkMxNUpGXp7xF33N0j3ClJT2G9Nt2oPbqEZglvw5mF3uP
         wT2g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent
         :content-disposition:mime-version:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=7YQ8Qr6dxvojqk2GUfhw92OP0JMAi8NnaDr6DLjC9P8=;
        b=x0rLAiVjum+QCXLqhIZCWE/yL4Q42IBmbs94zGP4AQ4d2bJNQUlUcAmCbZop42W0av
         rHA1q0TRu057xXxkuT2meSrY6IezwLKffNeC7SZD2seXUkfnFfCuiyH+H4gWnvrOl87/
         gM6Kpl/OJY0hsr2vXL9zBk46Y1Y8IP23tVv5fQO9ISREoXf+rZvIZuzNsLr6qV9td3K0
         Us1DzwGfRcBVenexevDvkoUm7WcSDGhTFe9za7cNxG9OQVXcCCYnObpHLt8fxKF0p26A
         vJSfgE0PC9rifcl8HYCjx1unub8UEZ6wMqAs+wkH51YhHYteen2OBePPBl4mzfhMc2JB
         DnZQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nOza3uqY;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::336 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:mime-version:content-disposition
         :user-agent:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=7YQ8Qr6dxvojqk2GUfhw92OP0JMAi8NnaDr6DLjC9P8=;
        b=Kn/mQD4rV1k1L7I7x72oc2R1IYrlXrpcxKFAY7VDYmYuwqYaR3iSxy1RXU6e+M3EaJ
         OaYcLy3Ro841a1NELaimSj2ZHDnFZo7bbWFd4qa0Na3+eCVDvy+hdOjwEa4wg3TmyRpY
         +kPoanKmWdh80XTzEX6FMmh3Fi3HUnZ3Yzovqz7VqWiR/83Lg5oIeojla+9/+qejV6En
         rrnsgIoYETS/vAE7JROQx6io/1glU5Ld7eLoN8NVp6JJzhnvivNIxp4tXGP++QGZ5sKV
         mif1MtxRJ4CHGCriiGXcl5LsarJGljtqlB1yTlnrpMUVNsxVEHZnjPJMxQhM8vP8QBlP
         RYFg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:mime-version
         :content-disposition:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7YQ8Qr6dxvojqk2GUfhw92OP0JMAi8NnaDr6DLjC9P8=;
        b=lnrCX2l3DATyIdiSHifsRefvByLauYEwIwQYC/m43G/s0M2RAF0V/tN7kBuZI/rM3W
         eAJ4Gzo2Qs64Ujvi8lx4NF7TQmwUajndZWEGoJ6673upgiKB67Fpe+FXOWDyAPPK9E3D
         jRBJLu55ylBCvYxXA26GevjApMRCK/SvSFA0fXtwx0H0jfIY0ic8LnyZgBQpysJyptBH
         XDxJNa74FXcKiNRQzBZf5FLLP0Ysbq0MZrL2s4MGo9mGQwcy9Qg5Orl+H7cKSLlV2Pxw
         5QE82X76ObgP2EZDd+21JrH7Tr8zqhpt8cFy4HzviAqx2J86WMSFexfsSVtjW75fttpX
         930w==
X-Gm-Message-State: AOAM531X7s/mGCTtkQg/Q8MyK1Y6MAV17GetGDPTbcI5j+GUFgm/c2WZ
	8832rG2mCTPuIlDaJAFWqbI=
X-Google-Smtp-Source: ABdhPJyU/7vh6gQDHwICvNl4gndNDcv0Cn2wMUAPH7EOlqGrzUrugFxuSDubGf0T5rt66bNMQuckZA==
X-Received: by 2002:a17:906:9512:: with SMTP id u18mr396142ejx.61.1622453830446;
        Mon, 31 May 2021 02:37:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:1c97:: with SMTP id cy23ls6661084edb.0.gmail; Mon,
 31 May 2021 02:37:09 -0700 (PDT)
X-Received: by 2002:a50:fd9a:: with SMTP id o26mr24047655edt.76.1622453829415;
        Mon, 31 May 2021 02:37:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1622453829; cv=none;
        d=google.com; s=arc-20160816;
        b=xOFbxB4VH6LSjnFfvTzaXj3G66yrjH6KkP8lqAPHVBrPuUa0PwjCf1Qbpu/ff5g5p9
         YIvXpMlIEgthIs5YnJXIMJSO9Nxdhe8qOQfGX1GxDGv5EQQiorOZNxMTPaxkVUjdCEHM
         2UVDNbpbRD0HVS9y4x99JDLhvqZtTTC4EbowEJDRkR5sfecuc1QhHrZH7dFJpNEQ9uMX
         UVO7YNTYDPzjmWWJ03/3/OWbasTzHXMiu1ehlN44Z0lhjdbRU7DQoBK5lhNwJQuK/m1p
         mqMDhBvATb/T0CNb+OWKBj62GI+ToGN/gVHGuJrGVxeAhS8qfRO0pxG1yE44uEQKONWZ
         ojAQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:content-disposition:mime-version:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=AIJ9Ja9r+6K9+GoGmxQcokEE7PPi9N4DFkhPombSqvY=;
        b=dlI91EnNrFGQLgBVq6g0N87nXaDIPhK0DOI8aTVT8ptVE5n1rP9X1mtDVDysbQ3FE2
         QDnceTC1Yt35kSsLzlXTJj+XtlYySwSJj1dSk65fIO3DvL6hy0qYTj3V7A2Ezf2dm1eo
         iUvdVqROKdFKbQX+wMA2D7uaBOzt/nZc212TnV6vhVD4EQwSK39OiQsejnWBk/0QGBo9
         4KBjRslOWnR5yNAi+5K428vma392KMU+Gz6dPndcX0cYNDA3q8KwRfYA0Ijf5RIqc68i
         hMUKlzNuehd/4Ww6OfRUvnFJUz+8GCK/xlHpKO64+SdOSRqBbtwmN6GNqjCZzksK3yVL
         dXtg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nOza3uqY;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::336 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x336.google.com (mail-wm1-x336.google.com. [2a00:1450:4864:20::336])
        by gmr-mx.google.com with ESMTPS id r20si288409edb.3.2021.05.31.02.37.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 31 May 2021 02:37:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::336 as permitted sender) client-ip=2a00:1450:4864:20::336;
Received: by mail-wm1-x336.google.com with SMTP id o2-20020a05600c4fc2b029019a0a8f959dso2894921wmq.1
        for <kasan-dev@googlegroups.com>; Mon, 31 May 2021 02:37:09 -0700 (PDT)
X-Received: by 2002:a1c:a550:: with SMTP id o77mr18965804wme.57.1622453828956;
        Mon, 31 May 2021 02:37:08 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:15:13:79b2:9d30:345a:1523])
        by smtp.gmail.com with ESMTPSA id n2sm18011994wmb.32.2021.05.31.02.37.08
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 31 May 2021 02:37:08 -0700 (PDT)
Date: Mon, 31 May 2021 11:37:03 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: paulmck@kernel.org, Boqun Feng <boqun.feng@gmail.com>,
	Will Deacon <will@kernel.org>
Cc: Dmitry Vyukov <dvyukov@google.com>, Mark Rutland <mark.rutland@arm.com>,
	kasan-dev@googlegroups.com
Subject: Plain bitop data races
Message-ID: <YLSuP236Hg6tniOq@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=nOza3uqY;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::336 as
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

Hello,

In the context of LKMM discussions, did plain bitop data races ever come
up?

For example things like:

		 CPU0					CPU1
	if (flags & SOME_FLAG) {...}  |  flags |= SOME_OTHER_FLAG;

	// Where the reader only reads 1 bit, and/or writer only writes 1 bit.

This kind of idiom is all over the kernel.

The first and primary question I have:

	1. Is it realistic to see all such accesses be marked?

Per LKMM and current KCSAN rules, yes they should of course be marked.
The second question would be:

	2. What type of marking is appropriate?

For many of them, it appears one can use data_race() since they're
intentionally data-racy. Once memory ordering requirements are involved, it's
no longer that simple of course.

For example see all uses of current->flags, or also mm/sl[au]b.c (which
currently disables KCSAN for that reason).

The 3rd and final question for now would be:

	3. If the majority of such accesses receive a data_race() marking, would
	   it be reasonable to teach KCSAN to not report 1-bit value
	   change data races? This is under the assumption that we can't
	   come up with ways the compiler can miscompile (including
	   tearing) the accesses that will not result in the desired
	   result.

This would of course only kick in in KCSAN's "relaxed" (the default)
mode, similar to what is done for "assume writes atomic" or "only report
value changes".

The reason I'm asking is that while investigating data races, these days
I immediately skip and ignore a report as "not interesting" if it
involves 1-bit value changes (usually from plain bit ops). The recent
changes to KCSAN showing the values changed in reports (thanks Mark!)
made this clear to me.

Such a rule might miss genuine bugs, but I think we've already signed up
for that when we introduced the "assume plain writes atomic" rule, which
arguably misses far more interesting bugs. To see all data races, KCSAN
will always have a "strict" mode.

Thoughts?

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YLSuP236Hg6tniOq%40elver.google.com.
