Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBY4XUCJQMGQERP46LTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 9F14951017D
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 17:12:36 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id f19-20020a0565123b1300b004720c485b64sf2324254lfv.5
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 08:12:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650985956; cv=pass;
        d=google.com; s=arc-20160816;
        b=gpztguqySdJkH9qA2I27AGVp37w6Bap7vxTKIEnU4d6AKYwPXDtnGy1OrRcI/O6hfp
         1VMCVvXmpBxABm0ZwDYPawYlYNPH6r1RvKISI8AM9cyr21tjoGumnR3jhTHfOZkzQ3Z2
         +tUrIkSoS4oy1VcExylUyhHGK9psobnX/+OqMzljbw7jdyKyHGUKtGI4x/wvovU8Q6Us
         13sDJj3NyIe11ppk618dd7R1XZ2vMf7kbHGzg++lNSOHFzBMq6OSSSP7MxxiCmycUfrM
         jPLDPmfZ3nnhPCUMCYdrTAYMVR4cJhQhNVTG5gorEBX3REzlvL5qh+yfFRRWqNh2oXPE
         EV/w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:subject:from:references
         :cc:to:content-language:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=TWXg5lo4P1scSnj7meIlPQ0frvjlNzQgfnvZyI8mpa4=;
        b=VGjm1UqSBoSD74p8MEbK9YdA9sgv2j6QKD5yoxpdU3m+ZMJMawXgedPQQDHITWOIZu
         z5KEUfhSx/1RjkrlTL03upDDJ9f3V0TZXjW+mFjvM2R70LXMrrQelTvSAB0LFjxKXRfm
         jx2NfDBQNBtcEr67n2Q7Q/QT/xKDvkems3jkvrvxKhktV0Jiep8IEfwSIBRXtLDbOGRj
         Kvik72Gz7XRhvj9FG6Bafmynu3g5JeL6U1j4IAJLKURBxWVaCEorDfoFTEGMra9Yg+yO
         S26r/xeHl0wY8Lcpg/Ww/E3qhVZsEuuJpqsMDc1UEfoBgevf1lzri4WzKmvu8DB3fYoh
         x7Dw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=mdJ1KGIH;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:mime-version:user-agent:content-language:to
         :cc:references:from:subject:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=TWXg5lo4P1scSnj7meIlPQ0frvjlNzQgfnvZyI8mpa4=;
        b=snVssIfutxsDgEm/Xc7f9dfMBjBwNobncdp5khHVHQDTOu6yFCd/Riwk4rA4DAY5OH
         f4Ba3NLbuR5kwG6lEJgVw+YfGFqNT5xQWVF5+1tpCM7i8sU4xJwtnVqrHOKQx/d+gxIt
         BHCoqgL3IuKEXN+YbAJof1KYN9MlEBYxaLr7oGH15f1ocB7FsCXRNseWRTP9cJdsW/GV
         WsCTPhcg2iSNTtcbVe5cTjeWsP5i9xsmdgflf5JwyjVQf0A7TODqk9D285rxmhZWK4Fe
         aDtvFTUkO1YxAkHDToQrg15mFXDPL44jeyO5rhpIdOlzgquIoqFaTdIuVVEqQd+IOfiJ
         oQ1w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :content-language:to:cc:references:from:subject:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=TWXg5lo4P1scSnj7meIlPQ0frvjlNzQgfnvZyI8mpa4=;
        b=cNLAJDPaiA3pwIRgUmDpwjXC7Zx/FgS/nVKNbr3iFC49iPunRt7PkWcs7zwIo70Jt/
         kc+NrqE5wKvvjoeuGw1qt14XIzu2+vt3LxpGlqKqkC+Zb3x9bfW9gAhFRImns8SPnri3
         Y6zKXdBYnDF8GPSAtVWR9plpemmTIfeiUKJd7PMO539S3i5XOg+FPEAQt1/UpMXUXC8p
         KaVOhWFFu/8mRa4nxZqllXdIge74RO6HYoIqEmyy7svfS9t1Pj49hMfK9iVY+kF+93l8
         re0VyWGyPV5AO7tmBw3ZBx0gsuV7NHTDlFnNIJOAW0gTIQiHCyWXYjJNevnP5DFtswJn
         Cseg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532nodCgJNGlkOQs+fhd2LI2D0ZGQk4HwEzqfEbMpvt/ogLXsWh8
	Bx49oxavO7pv+NlUdjGNDjc=
X-Google-Smtp-Source: ABdhPJwmyfpikeAyH4QSIfPESW3RA0cifTvB9sXSMaAQ7DkGwOhQ4HMdoy/4w0onGewYavjtHYYNmw==
X-Received: by 2002:a05:6512:139f:b0:44b:36e:b50f with SMTP id p31-20020a056512139f00b0044b036eb50fmr16930477lfa.594.1650985955814;
        Tue, 26 Apr 2022 08:12:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1a22:b0:24f:170c:7b29 with SMTP id
 by34-20020a05651c1a2200b0024f170c7b29ls879823ljb.9.gmail; Tue, 26 Apr 2022
 08:12:34 -0700 (PDT)
X-Received: by 2002:a05:651c:1191:b0:24f:155d:1f26 with SMTP id w17-20020a05651c119100b0024f155d1f26mr4796505ljo.421.1650985954344;
        Tue, 26 Apr 2022 08:12:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650985954; cv=none;
        d=google.com; s=arc-20160816;
        b=FtxnnsBMlq2d0B/5TQ89qyXANwuNIN7TQF+hY5fn8Ds4iV0t3vV0DQbaVxWFtEvdz0
         5ZWZ1m0WSHxr9FVxsEkcAWaByGS5gsJkIO0aywHsZyfKlyyLlNbyTvlTuv0xYhFBlFtl
         P62wwLxI/Y0A62n12O0Nn84Q/H5uImlTY7vxyJeTiizxmvVuKA5zQ9CNfsusumod1f+e
         Wk8fHQIGlwiIQRAck8X3zWCuLHZM2zsat9chw2ybkU6/fxXJxbs99/m2nWS/DpoNcusg
         x+mUAAWa2tkIDSQnCmhYa3FMZjXUfseKkdpRDnzYD6P6EeeBwNgLtbMIDT6vKyP3sib0
         8gEQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:subject:from:references:cc:to
         :content-language:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=ilqNI6bkLcv0GvaJ4q+HJDdDtII/9oekltf7dQ89U9Q=;
        b=U63JD5AT51n2dmiueo3mHUhD0zKgmjf7ekKWAcGSdhX8jlM9WKaAQpB2hHIYNbkjNx
         b6Z9tCfY5PC3UbVfYPdkfnZgNLWBy8oK8gXm0BEhpzembeQ1vlrhUK9G9D3dhrwIEi1J
         j8wX8yV2JNWAyxekzEjgBzdCK1Z9eos8BHuYQ7HvWpjR0XQGfr4Wpb9yP/9MfyUR/K/q
         5f8lbvo7urCmOna2PQfhInAKBYnHhnlyKZZQ16xI2h66z1G7WEOoSu6frX0/obISslFm
         B/GGzq8lMuKAkdRjLkoW2hG3zF1ACrxyiZYdB1YP0gKQ1UAmN2sFDZ2r41wZoQpJXzaB
         ayJA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=mdJ1KGIH;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.220.29])
        by gmr-mx.google.com with ESMTPS id e9-20020a2e8189000000b0024eee872899si527830ljg.0.2022.04.26.08.12.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 26 Apr 2022 08:12:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) client-ip=195.135.220.29;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 884381F388;
	Tue, 26 Apr 2022 15:12:33 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 335FF13AD5;
	Tue, 26 Apr 2022 15:12:33 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id IIraC+ELaGIkXwAAMHmgww
	(envelope-from <vbabka@suse.cz>); Tue, 26 Apr 2022 15:12:33 +0000
Message-ID: <147b11c3-dbce-ccd3-3b0c-c5971135f949@suse.cz>
Date: Tue, 26 Apr 2022 17:12:32 +0200
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.7.0
Content-Language: en-US
To: kernel test robot <lkp@intel.com>, Peter Collingbourne <pcc@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Hyeonggon Yoo
 <42.hyeyoo@gmail.com>, Andrew Morton <akpm@linux-foundation.org>,
 Catalin Marinas <catalin.marinas@arm.com>
Cc: llvm@lists.linux.dev, kbuild-all@lists.01.org,
 Linux Memory Management List <linux-mm@kvack.org>,
 Linux ARM <linux-arm-kernel@lists.infradead.org>,
 Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
 penberg@kernel.org, roman.gushchin@linux.dev, iamjoonsoo.kim@lge.com,
 rientjes@google.com, Herbert Xu <herbert@gondor.apana.org.au>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 kasan-dev <kasan-dev@googlegroups.com>,
 Eric Biederman <ebiederm@xmission.com>, Kees Cook <keescook@chromium.org>
References: <20220422201830.288018-1-pcc@google.com>
 <202204251346.WbwgrNZw-lkp@intel.com>
From: Vlastimil Babka <vbabka@suse.cz>
Subject: Re: [PATCH v3] mm: make minimum slab alignment a runtime property
In-Reply-To: <202204251346.WbwgrNZw-lkp@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=mdJ1KGIH;       dkim=neutral
 (no key) header.i=@suse.cz;       spf=pass (google.com: domain of
 vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 4/25/22 07:12, kernel test robot wrote:
> Hi Peter,
> 
> Thank you for the patch! Yet something to improve:
> 
> [auto build test ERROR on hnaz-mm/master]
> 
> url:    https://github.com/intel-lab-lkp/linux/commits/Peter-Collingbourne/mm-make-minimum-slab-alignment-a-runtime-property/20220423-042024
> base:   https://github.com/hnaz/linux-mm master
> config: arm64-buildonly-randconfig-r002-20220425 (https://download.01.org/0day-ci/archive/20220425/202204251346.WbwgrNZw-lkp@intel.com/config)
> compiler: clang version 15.0.0 (https://github.com/llvm/llvm-project 1cddcfdc3c683b393df1a5c9063252eb60e52818)
> reproduce (this is a W=1 build):
>         wget https://raw.githubusercontent.com/intel/lkp-tests/master/sbin/make.cross -O ~/bin/make.cross
>         chmod +x ~/bin/make.cross
>         # install arm64 cross compiling tool for clang build
>         # apt-get install binutils-aarch64-linux-gnu
>         # https://github.com/intel-lab-lkp/linux/commit/3aef97055dd4a480e05dff758164f153aaddbb49
>         git remote add linux-review https://github.com/intel-lab-lkp/linux
>         git fetch --no-tags linux-review Peter-Collingbourne/mm-make-minimum-slab-alignment-a-runtime-property/20220423-042024
>         git checkout 3aef97055dd4a480e05dff758164f153aaddbb49
>         # save the config file
>         mkdir build_dir && cp config build_dir/.config
>         COMPILER_INSTALL_PATH=$HOME/0day COMPILER=clang make.cross W=1 O=build_dir ARCH=arm64 prepare
> 
> If you fix the issue, kindly add following tag as appropriate
> Reported-by: kernel test robot <lkp@intel.com>
> 
> All errors (new ones prefixed by >>):
> 
>    In file included from kernel/bounds.c:10:
>    In file included from include/linux/page-flags.h:10:
>    In file included from include/linux/bug.h:5:
>    In file included from arch/arm64/include/asm/bug.h:26:
>    In file included from include/asm-generic/bug.h:22:
>    In file included from include/linux/printk.h:9:
>    In file included from include/linux/cache.h:6:
>    In file included from arch/arm64/include/asm/cache.h:56:
>    In file included from include/linux/kasan-enabled.h:5:
>    In file included from include/linux/static_key.h:1:

Hmm looks like a circular include, cache.h is too "low-level" in the
hierarchy to bring in kasan->static_key->jump_label.h definitions?
jump_label.h does include bug.h, but we have it above already and have
already passed #define _LINUX_BUG_H.

So, a different kind of header with arm64-specific variant?

>>> include/linux/jump_label.h:285:2: error: call to undeclared function 'WARN'; ISO C99 and later do not support implicit function declarations [-Wimplicit-function-declaration]
>            STATIC_KEY_CHECK_USE(key);
>            ^
>    include/linux/jump_label.h:81:35: note: expanded from macro 'STATIC_KEY_CHECK_USE'
>    #define STATIC_KEY_CHECK_USE(key) WARN(!static_key_initialized,               \
>                                      ^
>    include/linux/jump_label.h:291:2: error: call to undeclared function 'WARN'; ISO C99 and later do not support implicit function declarations [-Wimplicit-function-declaration]
>            STATIC_KEY_CHECK_USE(key);
>            ^
>    include/linux/jump_label.h:81:35: note: expanded from macro 'STATIC_KEY_CHECK_USE'
>    #define STATIC_KEY_CHECK_USE(key) WARN(!static_key_initialized,               \
>                                      ^
>    include/linux/jump_label.h:313:2: error: call to undeclared function 'WARN'; ISO C99 and later do not support implicit function declarations [-Wimplicit-function-declaration]
>            STATIC_KEY_CHECK_USE(key);
>            ^
>    include/linux/jump_label.h:81:35: note: expanded from macro 'STATIC_KEY_CHECK_USE'
>    #define STATIC_KEY_CHECK_USE(key) WARN(!static_key_initialized,               \
>                                      ^
>>> include/linux/jump_label.h:316:3: error: call to undeclared function 'WARN_ON_ONCE'; ISO C99 and later do not support implicit function declarations [-Wimplicit-function-declaration]
>                    WARN_ON_ONCE(atomic_read(&key->enabled) != 1);
>                    ^
>    include/linux/jump_label.h:324:2: error: call to undeclared function 'WARN'; ISO C99 and later do not support implicit function declarations [-Wimplicit-function-declaration]
>            STATIC_KEY_CHECK_USE(key);
>            ^
>    include/linux/jump_label.h:81:35: note: expanded from macro 'STATIC_KEY_CHECK_USE'
>    #define STATIC_KEY_CHECK_USE(key) WARN(!static_key_initialized,               \
>                                      ^
>    include/linux/jump_label.h:327:3: error: call to undeclared function 'WARN_ON_ONCE'; ISO C99 and later do not support implicit function declarations [-Wimplicit-function-declaration]
>                    WARN_ON_ONCE(atomic_read(&key->enabled) != 0);
>                    ^
>    6 errors generated.
>    make[2]: *** [scripts/Makefile.build:122: kernel/bounds.s] Error 1
>    make[2]: Target '__build' not remade because of errors.
>    make[1]: *** [Makefile:1283: prepare0] Error 2
>    make[1]: Target 'prepare' not remade because of errors.
>    make: *** [Makefile:226: __sub-make] Error 2
>    make: Target 'prepare' not remade because of errors.
> 
> 
> vim +/WARN +285 include/linux/jump_label.h
> 
> bf5438fca2950b Jason Baron     2010-09-17  282  
> c5905afb0ee655 Ingo Molnar     2012-02-24  283  static inline void static_key_slow_inc(struct static_key *key)
> d430d3d7e646eb Jason Baron     2011-03-16  284  {
> 5cdda5117e125e Borislav Petkov 2017-10-18 @285  	STATIC_KEY_CHECK_USE(key);
> d430d3d7e646eb Jason Baron     2011-03-16  286  	atomic_inc(&key->enabled);
> d430d3d7e646eb Jason Baron     2011-03-16  287  }
> bf5438fca2950b Jason Baron     2010-09-17  288  
> c5905afb0ee655 Ingo Molnar     2012-02-24  289  static inline void static_key_slow_dec(struct static_key *key)
> bf5438fca2950b Jason Baron     2010-09-17  290  {
> 5cdda5117e125e Borislav Petkov 2017-10-18  291  	STATIC_KEY_CHECK_USE(key);
> d430d3d7e646eb Jason Baron     2011-03-16  292  	atomic_dec(&key->enabled);
> bf5438fca2950b Jason Baron     2010-09-17  293  }
> bf5438fca2950b Jason Baron     2010-09-17  294  
> ce48c146495a1a Peter Zijlstra  2018-01-22  295  #define static_key_slow_inc_cpuslocked(key) static_key_slow_inc(key)
> ce48c146495a1a Peter Zijlstra  2018-01-22  296  #define static_key_slow_dec_cpuslocked(key) static_key_slow_dec(key)
> ce48c146495a1a Peter Zijlstra  2018-01-22  297  
> 4c3ef6d79328c0 Jason Baron     2010-09-17  298  static inline int jump_label_text_reserved(void *start, void *end)
> 4c3ef6d79328c0 Jason Baron     2010-09-17  299  {
> 4c3ef6d79328c0 Jason Baron     2010-09-17  300  	return 0;
> 4c3ef6d79328c0 Jason Baron     2010-09-17  301  }
> 4c3ef6d79328c0 Jason Baron     2010-09-17  302  
> 91bad2f8d30574 Jason Baron     2010-10-01  303  static inline void jump_label_lock(void) {}
> 91bad2f8d30574 Jason Baron     2010-10-01  304  static inline void jump_label_unlock(void) {}
> 91bad2f8d30574 Jason Baron     2010-10-01  305  
> d430d3d7e646eb Jason Baron     2011-03-16  306  static inline int jump_label_apply_nops(struct module *mod)
> d430d3d7e646eb Jason Baron     2011-03-16  307  {
> d430d3d7e646eb Jason Baron     2011-03-16  308  	return 0;
> d430d3d7e646eb Jason Baron     2011-03-16  309  }
> b202952075f626 Gleb Natapov    2011-11-27  310  
> e33886b38cc82a Peter Zijlstra  2015-07-24  311  static inline void static_key_enable(struct static_key *key)
> e33886b38cc82a Peter Zijlstra  2015-07-24  312  {
> 5cdda5117e125e Borislav Petkov 2017-10-18  313  	STATIC_KEY_CHECK_USE(key);
> e33886b38cc82a Peter Zijlstra  2015-07-24  314  
> 1dbb6704de91b1 Paolo Bonzini   2017-08-01  315  	if (atomic_read(&key->enabled) != 0) {
> 1dbb6704de91b1 Paolo Bonzini   2017-08-01 @316  		WARN_ON_ONCE(atomic_read(&key->enabled) != 1);
> 1dbb6704de91b1 Paolo Bonzini   2017-08-01  317  		return;
> 1dbb6704de91b1 Paolo Bonzini   2017-08-01  318  	}
> 1dbb6704de91b1 Paolo Bonzini   2017-08-01  319  	atomic_set(&key->enabled, 1);
> e33886b38cc82a Peter Zijlstra  2015-07-24  320  }
> e33886b38cc82a Peter Zijlstra  2015-07-24  321  
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/147b11c3-dbce-ccd3-3b0c-c5971135f949%40suse.cz.
