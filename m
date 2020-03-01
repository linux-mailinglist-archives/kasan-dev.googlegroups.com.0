Return-Path: <kasan-dev+bncBDQ27FVWWUFRBHX36DZAKGQELUPLWMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe38.google.com (mail-vs1-xe38.google.com [IPv6:2607:f8b0:4864:20::e38])
	by mail.lfdr.de (Postfix) with ESMTPS id B58C41750AD
	for <lists+kasan-dev@lfdr.de>; Sun,  1 Mar 2020 23:56:31 +0100 (CET)
Received: by mail-vs1-xe38.google.com with SMTP id n129sf1339780vsd.4
        for <lists+kasan-dev@lfdr.de>; Sun, 01 Mar 2020 14:56:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1583103390; cv=pass;
        d=google.com; s=arc-20160816;
        b=U1jCjG4xsz12tXky8Kl2sRgvYYWxpV18IZhMG28vnZO9E+us6bObJgQG8ujwbDzBI+
         zQPaybEAxnV8nVG/CSJBIC0TAx0tynGqE/k/BUVJcTsxAKQDWTeNvMMDdKcEqQM4xNsT
         AsxZUNPBVMIU1P+BEAaSrvxXQ0BzNy21+jRLziJV1zNuYpVzaxcarRnqN8IJ1YfSFNuk
         MWOqxRd+Wjd6LVRUQ4L03CQcg/QP1YTkhmXojdVInwLqm3CtrYql+zQp6JBheGs+BO4y
         FKBh+dyHGyldJCj8lyuG0fYCC1R8nuImiH0bBDVqPcBXWB4ArBveGYwAgBDZ+abg+FVi
         60Sg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:to:from:sender:dkim-signature;
        bh=zoxiclBuWx2JBDj7aUkJVSkvHz7KgiQn9w/qs5vrmwo=;
        b=LvO7PTri/JMO93C8+RsoHbtfyetqCGneHdNFzOwuxcKjZikOd4LhdX/3gv7s7VYtz4
         Hqp2sjjlF7CsPvopIQ2ub2dElps6PEW3BlCfqU3E1NCx6t32gFTM36adSlgOreypwDPr
         pr/WJs0tFfV5NQrUVbPE8/fBw4avEd67K/ZJRGnf1SLmXVReCik/VQ0GRzejcb9RYLFA
         ChFq9+SGEU2aFAyrBcXXb/H+eS7MA9ZGZu1Ed4S14fbvrQralCS+r40XhcDk2RHe8wsU
         4zUZZZQHklh4KPdWjgKuQj6G9axO7v2s5G0YPfZzRC1fmiPFv0eKWnwEaMoPZCQZISQ6
         XV+w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=ASBynYC7;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::442 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zoxiclBuWx2JBDj7aUkJVSkvHz7KgiQn9w/qs5vrmwo=;
        b=WwNptQ5kS8XJPR7Mziad4AGjtYJLYSuXFYv2KLUTSBfXCLv3bLOEEYkC7Vn4pEyJ1N
         UD+BNTZoGrXEUYf5vho0aHask2+LRPPZT3dhagrcYzqob6jOy+KYlUcXrgLyoGGgCroM
         IeoZ7xKe0XwR3ND6KBYq3KpHBDWhLVWxO3/1IHIhbC9BWujFEK2qCVrY9WaSnsilXBAC
         LTSzAOhkuKf+tE2aRS2KoxNbxM4gGjDnMNIP+Eo3AG7WLHnZ329YmvsnsLgs/2/x8Sut
         BkwO/iPwLOTzKXhL6YFcEXM5XUVujFCJTGiFtYX9pOkPZJHqOgT0wA77/+DEpBCpY5aw
         M9nQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zoxiclBuWx2JBDj7aUkJVSkvHz7KgiQn9w/qs5vrmwo=;
        b=BRl1R9YLS+wK8auxXrM1sD4LSrza1m7Sj/q/OvBlmHoWXTkILSl5JLVnc5Ry+x7gGP
         vPreq+V3QbJPL1VXhWA6D4zyi/6ZH+pmyBOFTLXvYvwJiR/LGpTT+ZY9JJ5BEwmUmXTY
         vgwNTtwulL5N7gfCJCZTJ8UK8aB10/0Rur6hA97yPHfFBzWdpBe8/YGAk9RuHVIEMR/9
         yCvc7T5CAV8KahZblahzxqhK6fViWW/ovTFPqbidRU0MRJNYlWKqCL3inzAa7hcN01kF
         WjJTkLN8nJvUvwJ0EFYH/Fh66v0fSooVTysIWLnyM9Bqmj0+Z+SZplJmZgc92Q9pRbs8
         ka/Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ3JH/TsYTt9Pu66oSy//nyCpaFxUZGOXGvXHgHcPtIj7FbyNXnk
	eA85u3ngMLndEY1HPrRNitk=
X-Google-Smtp-Source: ADFU+vuiyuKay04DMDpX7gaxv4lp7qYLl1X5hlxf5oepF0zhuEAHIpzRAsQoenKDjjlE1Z0A0tzgJg==
X-Received: by 2002:a1f:200e:: with SMTP id g14mr6020394vkg.45.1583103390758;
        Sun, 01 Mar 2020 14:56:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:e30b:: with SMTP id j11ls24621vsf.11.gmail; Sun, 01 Mar
 2020 14:56:30 -0800 (PST)
X-Received: by 2002:a67:ff01:: with SMTP id v1mr975423vsp.185.1583103390435;
        Sun, 01 Mar 2020 14:56:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1583103390; cv=none;
        d=google.com; s=arc-20160816;
        b=pHX2XqAsuZJOVR/bT7Q92UhBSza10/JFn+zyiqPsI7naXLLxbIeF4xuP0qL5yEoiwf
         tZWNJqTqVoKgDUjf+zTEZVKnwVTFGVQw8JZwI0Q7K/S0G2uOC7oumgO88ECa493ojLgQ
         1eOagR/xwIHX+Fs6qgomFOUBalw8tX5II+hgSfH/JEqTamcYaH4pAwT75ffw0WWuaP6r
         6BuG9JwKoJCYBXSyISr5ZU2YG2QwkfHsDNrL5is7tH3zId5hVx9/Zcpob8q6rXxmdS7z
         9SO4TdHwiVYa0A1rneWqrEa45FnhEza6/Nkz5InIzJYkxqhvbxRb0SdEcfQ/lwn1QOap
         Xgig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:to:from
         :dkim-signature;
        bh=se0IyZ7gHAr6eXWZqvCMUC+l5nOCWe5ipTBvljrrVTM=;
        b=G9uP4DqiARQ22JLZN4BWgAtvy22wCdDGo6hK5T6E0LmXgpdJ1cegt1it+hYK6TOHz5
         RGrY5LTthSD8xCW+elq5g64R4IuOPvx3u+m3jE7und1HXpwFqntFD3pj3qlXF98eW72U
         c8yojkyJcTV+mmLGydtEqYLkqhykifslK2291rnbA1OJdC/iJECnYORau/Biy//CUrfG
         CQ86Hc45dWQbAhJcdo9tUFCnNEEOLqe/BAy51EUs3PVlBdkvX1TqoB2TVDDdQ4bJOjBn
         HaW6MOYo9k7AIJ6NipSac6cf0b98QdVu8zpeGtWn9GXk2nhP89MgNjgad2nN3jE3aYy/
         A7Iw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=ASBynYC7;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::442 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x442.google.com (mail-pf1-x442.google.com. [2607:f8b0:4864:20::442])
        by gmr-mx.google.com with ESMTPS id r6si562861vkr.0.2020.03.01.14.56.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 01 Mar 2020 14:56:30 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::442 as permitted sender) client-ip=2607:f8b0:4864:20::442;
Received: by mail-pf1-x442.google.com with SMTP id l7so4604107pff.6
        for <kasan-dev@googlegroups.com>; Sun, 01 Mar 2020 14:56:30 -0800 (PST)
X-Received: by 2002:a62:5bc7:: with SMTP id p190mr14926424pfb.16.1583103389485;
        Sun, 01 Mar 2020 14:56:29 -0800 (PST)
Received: from localhost (2001-44b8-1113-6700-591b-db3f-06cb-776f.static.ipv6.internode.on.net. [2001:44b8:1113:6700:591b:db3f:6cb:776f])
        by smtp.gmail.com with ESMTPSA id h2sm17797020pgv.40.2020.03.01.14.56.27
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 01 Mar 2020 14:56:28 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: syzbot <syzbot+be6ccf3081ce8afd1b56@syzkaller.appspotmail.com>, arve@android.com, christian@brauner.io, devel@driverdev.osuosl.org, dri-devel@lists.freedesktop.org, dvyukov@google.com, gregkh@linuxfoundation.org, joel@joelfernandes.org, kasan-dev@googlegroups.com, labbott@redhat.com, linaro-mm-sig-owner@lists.linaro.org, linaro-mm-sig@lists.linaro.org, linux-kernel@vger.kernel.org, maco@android.com, sumit.semwal@linaro.org, syzkaller-bugs@googlegroups.com, tkjos@android.com
Subject: Re: BUG: unable to handle kernel paging request in ion_heap_clear_pages
In-Reply-To: <0000000000003eeb63059f9e41d2@google.com>
References: <0000000000003eeb63059f9e41d2@google.com>
Date: Mon, 02 Mar 2020 09:56:25 +1100
Message-ID: <87blpfr8fa.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=ASBynYC7;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::442 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

syzbot <syzbot+be6ccf3081ce8afd1b56@syzkaller.appspotmail.com> writes:

#syz fix: kasan: fix crashes on access to memory mapped by vm_map_ram()

> This bug is marked as fixed by commit:
> kasan: support vmalloc backing of vm_map_ram()
> But I can't find it in any tested tree for more than 90 days.
> Is it a correct commit? Please update it by replying:
> #syz fix: exact-commit-title
> Until then the bug is still considered open and
> new crashes with the same signature are ignored.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87blpfr8fa.fsf%40dja-thinkpad.axtens.net.
