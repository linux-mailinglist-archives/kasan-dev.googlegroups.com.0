Return-Path: <kasan-dev+bncBDW2JDUY5AORBMWD26LAMGQE7BUPSQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id AB239578DA8
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jul 2022 00:41:55 +0200 (CEST)
Received: by mail-il1-x138.google.com with SMTP id n16-20020a056e02141000b002dabb875f0asf8346124ilo.10
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Jul 2022 15:41:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1658184114; cv=pass;
        d=google.com; s=arc-20160816;
        b=kLb3HU1tp/mJ/bUAIedkY9LM3uzm2bRt5pZv7oR7EHsy6GV8Q+7FmzefOLinHeitTj
         NyFYmWG00l0Rsw47WmeOdUmrKdz7nzUzdDKK6P1uIw6cP4cryr7PmvAH0byQTZIVQCBB
         bK/S8MIVDLXH8PnyeMOieUuuE4XSXEWjK1JKtaVkdUjT/sKXFuBqXKFn8lJ/kmtF3DBN
         XKUPVeEeUMt/6o5W5gOqKBfgDvcWQLF9AoSAaFQHdDowcE+OGFLN78WqCSxxgMEgJnUZ
         BeKMBtpB25yQWyMWG7QfR3pHSRtfvOy8vbD35q9hHvSEN6OGs898Jfb1UqHfKqJ23MG9
         c7FA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=4ojJ2ucBUcXoK+Y2GS4wxg/hQDg40kKNz3QG5OCK9fs=;
        b=dGuVfUfBf7y+BH4b8EgYho6HpcGJsej5DYSuC3nK6I/h2e9bcg+X8COs2+FaHzce1z
         0GZ3O1bPZBs091QECATi2JPGu8Z7ADHNejMqHoQ+HhQBHy1tEGAp9vv5G1PUhXCk/Rqo
         C/uooNkr6iet623PeTP4p6kw6v0XjQvrtBPzahtUOiX77ZwKrridD87XFA7g6AIaj23l
         d2Pppmc8+xIK+fFLrJW+Qt2Y4H7W/ZyudZOLWqqBDpWBtZZg/o5K1+ixIt9AO2cXp0CT
         jHDLc0dYsBVfMMp5IasygAZFdVbXVLp3vDuneDDQzRBxPFM7H6Sx3phWeqJ1z3htYOcX
         U4Ww==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=c7f9jrMy;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::f29 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4ojJ2ucBUcXoK+Y2GS4wxg/hQDg40kKNz3QG5OCK9fs=;
        b=B+IJabIj1ggp73BlHRUvqK+m2hdGpSMGSRw1uB6RqDVn7i7PNC9hCUpKnoEhhxnyNq
         lwrrUADGIktvEqC3TjJEdOWkqonCGlJB+B82RgDOuib0TtvIRjBKQHMJNOf5Fyy8lOoi
         7p7OTjzmVgXxrknYrJ4DYzqWtphuBB0IYws+M6RVfnuwAG0YuRsb3gwh/q2SAYwK+Iw2
         yLQOtYqcajjEOdTa29rWO+HzLyePFMeWH9bkWFjskBGKfGq4xD+Nw3eOW73S/L1pnVIQ
         0/l4MxfIJJhruV/DXFbTYSlSQF3pqtbftGabjK378Ht5h1eNkPdAh7hxODoeOHbDRz3O
         JPfA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4ojJ2ucBUcXoK+Y2GS4wxg/hQDg40kKNz3QG5OCK9fs=;
        b=o+zCnRZU53XJLyycxMyx7Cg40XQOndFWIMxUPwBU+acEykORdZZF0PcC8hAEUKkO5k
         fMAG1ZSMRW6uk517qeT5+IKjtEy0ea8QzbZqigYQfoc1jObg7ohryH4zNqXOvda9UKYI
         gEMcoQhycfgZAto1Sn7KjH/Ky+JjH04UQGBsc1qU1nhLiyd0vxzLqwF82L7+ThdB6WGo
         2Xgw5PkyGgrmUAnB8/8P709EveC8QFLe38czJow6ji3t9OhJlhS/PkqUisoGhK7KNI0S
         cjWlfRoOTF4AAZIREgNd7QGs5qx7M9Qy9iwwVSzgMXjC32/FJTLt8mf4S1lU+3dli22h
         /khA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4ojJ2ucBUcXoK+Y2GS4wxg/hQDg40kKNz3QG5OCK9fs=;
        b=RghQ79HYiG1/Hzz3XL2oUVowOveZkNa1o/zKiYEtQ/fyQQG+BeUhqyPbJKXWOcIju+
         JcWNleCB1zf5YlJWC0bDYlCH+0zvX30kkqf0dcYW6pZf60pjulBFKuoYgp66CH4T6CX4
         CUWm6WO8p2aH1jLRtcPcDUlfHuXZEbyK5BrnIOsSfK2DPd3x1M3JTJQreaXOtrn4MaIK
         7Rbt5mRl5AIXlbVopTM8q4bQ+qURn8RgdA0qgaxpp6p9b+0mDP5RYgHBdwXTjrqeS02/
         t0EoVaci3a6xPlaEcTEvkpvg9q9ZNe2avqFjmNjcJfG2ZKqxsi4apw3ONksMBbUvFuks
         7KvQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora/ZKfb3bGg+HJ3N0PFd/lt78aNZTUBbwZckGhSHQk/hpo51/iNu
	/78c0XgIf7rTd/ueNqQOrOw=
X-Google-Smtp-Source: AGRyM1sOiIn0M9JFLyX+Py4T7wgDm4dh8byqORlw+NetiDjwC/ECrJcedqOhWfXtyYd4tuvq/InZjg==
X-Received: by 2002:a05:6638:2596:b0:33f:8e41:a3b6 with SMTP id s22-20020a056638259600b0033f8e41a3b6mr13897506jat.266.1658184114381;
        Mon, 18 Jul 2022 15:41:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:1355:b0:60a:9e26:930a with SMTP id
 i21-20020a056602135500b0060a9e26930als7791644iov.7.gmail; Mon, 18 Jul 2022
 15:41:51 -0700 (PDT)
X-Received: by 2002:a05:6602:15c6:b0:67a:33d1:6c73 with SMTP id f6-20020a05660215c600b0067a33d16c73mr14410224iow.156.1658184111482;
        Mon, 18 Jul 2022 15:41:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1658184111; cv=none;
        d=google.com; s=arc-20160816;
        b=yAVFo1qZhxIQu/0JaSaghwylFH2Svf2y697SwIw4r9zxlU6AU3bnerXRx+vfzfrmZi
         MYMnh8JAk9IZjoCwDg/3XSHR20cyAF4Cj2eFYpWe448oxSJ+IvKZU02jU1J863f/1o/7
         oamLRJ3ZrObWE64e6pM3XuoIM6oAMr1PCA8VOKkPp8nWHFUl/+SvcZlvIVJvB1cvTh/b
         Q/gm8Joy+DJNx2mxnUhJAkiNttrtXrC7NN7VQqeV0ennrLKX+ZE1rI6L7lqwcYezF+VU
         Hs8Jmyc7Oa3kri4958IOdiEtA205fGIMRpLQc6Y5AMCklTpFdmwg0ZIsmYZztZO3S9L5
         xfyA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=YjeR/BKl7tGBTzlht0Fuz8ACOgbjgQ373S98IaM7eJ8=;
        b=I5Eg06lBQ1y2wEanSKIQooCKt6xleJIn1fFZ6IMTC9kaLAWq5LwfrE5a0gDc+KW2Bd
         LGv7XJUCkl4yXddWkq16Jg2AWIPOiFAhWU6hbgmIBUDESgASJiR2Pzf6gxVTRK6Ea8rZ
         2PmsKQDldne+iiViglk+dBPhyCBy5Ptij0Pen7aLtBOvKaUzwR6rgtMzyae2y1/Ybdvb
         6eLkBE1M74vRluHhSnn25b5NiNFhXRxlSn+pnVY/hUdNvhhGn7hZSG7/PoKUPkuaR2tq
         tfyDJ1nRk5kMqZ2PkByOOE2PrQ2h+iMjf0Pc5YrHwZn0+gbqGlJ1m3cNoJZqzc/WHooB
         9VJQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=c7f9jrMy;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::f29 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qv1-xf29.google.com (mail-qv1-xf29.google.com. [2607:f8b0:4864:20::f29])
        by gmr-mx.google.com with ESMTPS id t7-20020a056e02160700b002dc74a0e355si548639ilu.1.2022.07.18.15.41.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 18 Jul 2022 15:41:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::f29 as permitted sender) client-ip=2607:f8b0:4864:20::f29;
Received: by mail-qv1-xf29.google.com with SMTP id l2so9936210qvt.2
        for <kasan-dev@googlegroups.com>; Mon, 18 Jul 2022 15:41:51 -0700 (PDT)
X-Received: by 2002:a05:6214:226c:b0:473:25b7:fce1 with SMTP id
 gs12-20020a056214226c00b0047325b7fce1mr22964567qvb.56.1658184111244; Mon, 18
 Jul 2022 15:41:51 -0700 (PDT)
MIME-Version: 1.0
References: <5ea6f55fb645405bb52cb15b8d30544ba3f189b0.1655150842.git.andreyknvl@google.com>
 <202206152134.sadCRvGk-lkp@intel.com>
In-Reply-To: <202206152134.sadCRvGk-lkp@intel.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 19 Jul 2022 00:41:40 +0200
Message-ID: <CA+fCnZfs+CiBVBf0BYD2sp9KgO2+_QJOH=XaNVt7-kk4tdLy-A@mail.gmail.com>
Subject: Re: [PATCH 24/32] kasan: move kasan_addr_to_slab to common.c
To: kernel test robot <lkp@intel.com>
Cc: andrey.konovalov@linux.dev, Marco Elver <elver@google.com>, 
	Alexander Potapenko <glider@google.com>, kbuild-all@lists.01.org, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Florian Mayer <fmayer@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=c7f9jrMy;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::f29
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Wed, Jun 15, 2022 at 3:28 PM kernel test robot <lkp@intel.com> wrote:
>
> Hi,
>
> I love your patch! Perhaps something to improve:
>
> [auto build test WARNING on akpm-mm/mm-everything]
> [also build test WARNING on linus/master v5.19-rc2 next-20220615]
> [cannot apply to vbabka-slab/for-next]
> [If your patch is applied to the wrong git tree, kindly drop us a note.
> And when submitting patch, we suggest to use '--base' as documented in
> https://git-scm.com/docs/git-format-patch]
>
> url:    https://github.com/intel-lab-lkp/linux/commits/andrey-konovalov-linux-dev/kasan-switch-tag-based-modes-to-stack-ring-from-per-object-metadata/20220614-042239
> base:   https://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm.git mm-everything
> config: s390-allyesconfig (https://download.01.org/0day-ci/archive/20220615/202206152134.sadCRvGk-lkp@intel.com/config)
> compiler: s390-linux-gcc (GCC) 11.3.0
> reproduce (this is a W=1 build):
>         wget https://raw.githubusercontent.com/intel/lkp-tests/master/sbin/make.cross -O ~/bin/make.cross
>         chmod +x ~/bin/make.cross
>         # https://github.com/intel-lab-lkp/linux/commit/b0b10a57b2d9a5e5ae5d7ca62046b9774df1a88f
>         git remote add linux-review https://github.com/intel-lab-lkp/linux
>         git fetch --no-tags linux-review andrey-konovalov-linux-dev/kasan-switch-tag-based-modes-to-stack-ring-from-per-object-metadata/20220614-042239
>         git checkout b0b10a57b2d9a5e5ae5d7ca62046b9774df1a88f
>         # save the config file
>         mkdir build_dir && cp config build_dir/.config
>         COMPILER_INSTALL_PATH=$HOME/0day COMPILER=gcc-11.3.0 make.cross W=1 O=build_dir ARCH=s390 SHELL=/bin/bash mm/kasan/
>
> If you fix the issue, kindly add following tag where applicable
> Reported-by: kernel test robot <lkp@intel.com>
>
> All warnings (new ones prefixed by >>):
>
>    mm/kasan/common.c: In function 'kasan_addr_to_slab':
> >> mm/kasan/common.c:35:19: warning: ordered comparison of pointer with null pointer [-Wextra]
>       35 |         if ((addr >= (void *)PAGE_OFFSET) && (addr < high_memory))
>          |                   ^~
>    mm/kasan/common.c: In function '____kasan_slab_free':
>    mm/kasan/common.c:202:12: warning: variable 'tag' set but not used [-Wunused-but-set-variable]
>      202 |         u8 tag;
>          |            ^~~

Will fix both in v2. Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZfs%2BCiBVBf0BYD2sp9KgO2%2B_QJOH%3DXaNVt7-kk4tdLy-A%40mail.gmail.com.
