Return-Path: <kasan-dev+bncBDQ67ZGAXYCBBD4XV7CAMGQEYNFFIEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 82077B176E0
	for <lists+kasan-dev@lfdr.de>; Thu, 31 Jul 2025 22:01:21 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id 5b1f17b1804b1-455f79a2a16sf14607065e9.2
        for <lists+kasan-dev@lfdr.de>; Thu, 31 Jul 2025 13:01:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753992081; cv=pass;
        d=google.com; s=arc-20240605;
        b=JPKUI4/NqzyVPqMeG9nqQM5ONbbIEYuaEU9MZjk4RCeOI6z7NX8PS3f6PASyQyXGOi
         6/PtkLJxOhPwDFb+RebhuP9PNzeMDvl8EKcd8TzaAU3wKdeMNSIMS5h9Wxc86VJ/k+Hl
         Psd+SL0U7jcdxdfGDmMkewXOjVBj+0NS9wWGT/44yvJyKb2+dszTL0kuYFnThC1RxPRT
         AeKLGBOhxVlY3Abe0Dm/QMIovMgM2c/fb1vVicGZwS6DJYWFvyTxlua1iOXHNNWGrYKq
         uIME124NdfHSlZGfi3os5miXQjwGbfv7AvWSQiBFOI7yOvpMDwF9WX/jaivM5mlGjwGO
         DovQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=81eF2VrV0D8ed7BXXVflv5xpaMnX4OmY85WN28bHkS4=;
        fh=LMar5hC9UYGsDnc/0pP9rbYtD2zP0Xe41yd6QdOn0GU=;
        b=Je7mezyeHuZrO16APm8sEL3ZUurWbY6qIqJhDb+B/XRBVuEHrtlR+mufvvj4NVsfCZ
         Ot0XTd+LZnsXJy0ChM9NrE3s/+IH57sz1RQzb23ZSKGsAgsYflL5i+mkvn54sKysrQMS
         O/Wp+gfPtZBI4maQ/arV0k8ReBTY1wwoIlpKE9Fl1TRkbeA1soK66CVu4fn6y+jWO71G
         Ey5BnHp5J7x+gkuOx25eJxycwfIbOvtxTPsWREXplKKym8SH5taS7nxlRD+saMXODXcM
         77m9DgQRSVOoP9X35NLnRyt9mgzgK6HJ2rgNkpU6a9gM8gKr+D1GluaT5TGCFXVorOAv
         0rDQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=1huudaXn;
       spf=pass (google.com: domain of marievic@google.com designates 2a00:1450:4864:20::52a as permitted sender) smtp.mailfrom=marievic@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753992081; x=1754596881; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=81eF2VrV0D8ed7BXXVflv5xpaMnX4OmY85WN28bHkS4=;
        b=J8COwUyvS4DW+xyFSLI3BJ4Qj3p/eKGEnVhxv1a6pYI82GUuxAdukp7hoAtx/divmu
         Ltz/eGgLd9uKWXXW4H3qV6BP0QB4LDSe/DHAalPIfPGHCz+WB3tGd5PPlfdQ1lQZc1Xi
         jaI5/M/5lIiH4ytYKBfA1E4AdyEiX7H3m5EtYKUoL3EkeCecMpQOoDinn6aqyoqmsdp9
         nZp3Mtx4kR516G9rEPEHcreb4Sqjk5s08Bs9V9OplMs3AwGYlig381qKFEaSzqAeBTxb
         acXvf4RDfVmLLprnAFhopY+3Rd13V21fNQVVMUYNjaNBOtAG1uOTL8S4Vo60dFrOwA9q
         5S0A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753992081; x=1754596881;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=81eF2VrV0D8ed7BXXVflv5xpaMnX4OmY85WN28bHkS4=;
        b=fhdv6Si7EWrLANzYnRfcUqbSTicRrhTGTAlG2HJZbGERb7TP50UG5DKDZ8mQVOtrPB
         GncCBjMykYqPvHHuevo0ATdfK2jWX/Z1Jf6J1pPrBzJBl4zH7nOvlSWmat/nG6jDS+PR
         8y4uYQawa4WwI7Z59xJNXIWYF9P3gvAJHtDGeUoO/xGunL4o4ga2R7i+8C/kUnA5Z9v4
         ANTWXXeqo/O7RSBcGhpGcy5vYvUvgJ5rPEItwlWLHL6bqJT6dD4nKA5lh3RnCY1JSvCG
         kCGUuOZaKe47mj0hkCqOthBXnv0tXD8JxRYz5pQFaU+cI/xoL8Q+uXZEr7+VotCZ78UG
         NTfA==
X-Forwarded-Encrypted: i=2; AJvYcCUycSanopGSP9ioxnB7cfSPMQGbQq2dRaJRRe+EWVK4F03HJPu4bTzwNpQNaKkWe7CSburRRw==@lfdr.de
X-Gm-Message-State: AOJu0Yzp2u7k/I22JZKwY+VhkUJxAsGxOWCFjl9P1sG3QD7H4NlCsnZI
	FRFEckh1wx6zJBKxoz0qVsXdF87Xdm1aLE+9WIZVoavlxKZeEg+kjO6o
X-Google-Smtp-Source: AGHT+IGrUyQfrt6cwdyuvBu55RIIuS9e1zO678wyRJqTlc4/ebdsYlOEgcrbWjtTw76VLIaRNx4K8A==
X-Received: by 2002:a05:600c:314e:b0:43d:fa59:af97 with SMTP id 5b1f17b1804b1-45892bebf5dmr74867425e9.32.1753992080573;
        Thu, 31 Jul 2025 13:01:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcQdIkbMNxJNriG8o29uI/8it8QkTnIqEghTLgIwOmN2g==
Received: by 2002:a05:600c:64c8:b0:43c:ef03:56fa with SMTP id
 5b1f17b1804b1-458a8827676ls1893375e9.2.-pod-prod-02-eu; Thu, 31 Jul 2025
 13:01:18 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUOFoKCs9BIYC2FbI/3Ys1gZrPNhPN5AoDJ8GVSbDD8ofxmKmnBFYepMXCn1V4ZCRO5lgFc9hmzQr8=@googlegroups.com
X-Received: by 2002:a05:6000:400c:b0:3b8:d32c:773e with SMTP id ffacd0b85a97d-3b8d32c79ffmr194919f8f.36.1753992077856;
        Thu, 31 Jul 2025 13:01:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753992077; cv=none;
        d=google.com; s=arc-20240605;
        b=W4yaKQSyPQRKC34FB674vHAYaRQpXWfaORd+11piJadJ0JD/pFGJRMuGEoyZWMCXMX
         OSKym2Xa5ad1zmn55NYYW91Tf+Nj046ijNccpYUegh4eh+sXrHRDTZoK0l33xQ71m72m
         noRe5fEozyznqkCZ0i1ABpLAhphITihnS2hDTu4rK9afy0EsPNYyIF3LtqiBWsSd7MbC
         nuIo8uGbIdFVuBoId5qdrevRT962XlpoGrP0oF5Z63qaSVGcT4HAq8VZgwfkMcEhWL34
         LXyQgAixLIZ/Rc/Wq7V3ZdFKWpxLdfNILhx7cFDvsViocQQGDqQWZwvT3YcX7sLXjEOV
         jKBg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=j4B+Gc5g7Q5xkPte+e+rtUPltSMHyDQNEhLddUtHkKo=;
        fh=ueH8OeKZ2LoFrWxnZvRqOucac5+1SV8f7rV24HXaDHs=;
        b=j17jJjSj4X//G4I6mOF7Pe2P+c8FshTV8cgYZsHInavs/yoZUva6njil9swLpsyWMT
         PoOTED3OpDdqXrL+27LXl7+Zd/2hrI6YqSn2Eh5wkOYnbbZ1F7pt6ModVN4njKfmuecS
         xLdP8jimt/mN1kj92m5QI2i/IkwV+67JNMoJ8P2/4Ruz16pUgH6mvdmdI7A0m3adROHp
         tx+vj9G6MejnTi+Jx0A9W72TrRnD4C9lblp6xjg7D5lwmktrX+R5AWR94yNP23UnKdLS
         sTRH8WY3jvaT5lcfJ8uWg8jMgSy7dxZPn7IjId4RTD3ss7f7ph3iK2JUHc3ku/FqJzPw
         wmmw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=1huudaXn;
       spf=pass (google.com: domain of marievic@google.com designates 2a00:1450:4864:20::52a as permitted sender) smtp.mailfrom=marievic@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x52a.google.com (mail-ed1-x52a.google.com. [2a00:1450:4864:20::52a])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3b79c47aa0esi70210f8f.7.2025.07.31.13.01.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 31 Jul 2025 13:01:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of marievic@google.com designates 2a00:1450:4864:20::52a as permitted sender) client-ip=2a00:1450:4864:20::52a;
Received: by mail-ed1-x52a.google.com with SMTP id 4fb4d7f45d1cf-6156c3301ccso2661a12.1
        for <kasan-dev@googlegroups.com>; Thu, 31 Jul 2025 13:01:17 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVjBfiBw4FpAajVTxaa1N9vKykPbPnYglGfzpURCw8bSNS2CGB9hR2KWs1SAkpKIEbpdhmT2F6CGZo=@googlegroups.com
X-Gm-Gg: ASbGncsJGlfrL2sF1Fz7sGvaiQnPkqzrdCg+fFnv3gmhwDw13FkNC+ls7wQtAo+z5Dl
	VFNhOsvbCG0oiCWXjhg16BYA19+Ulp6zsTJFnO+we9hF0rvPRd4JS0M1+66ChfvGJXhpm5Nv4a9
	jq164WFfuj7Ofyy0ZpXiR8Ujn01fqDppX1vyApQIgzjfiYWEqrJ5ENPK5xJ+LBIeDbkjqtUcGYY
	QCRPdiHDNRK7Cbyec2RBu4LCp1nGjPwCCDCZw==
X-Received: by 2002:a50:aa8b:0:b0:60e:2e88:13b4 with SMTP id
 4fb4d7f45d1cf-615cba4acfbmr10864a12.3.1753992076959; Thu, 31 Jul 2025
 13:01:16 -0700 (PDT)
MIME-Version: 1.0
References: <20250729193647.3410634-7-marievic@google.com> <5683507a-dacc-4e46-893f-d1e775d2ef22@suswa.mountain>
In-Reply-To: <5683507a-dacc-4e46-893f-d1e775d2ef22@suswa.mountain>
From: "'Marie Zhussupova' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 31 Jul 2025 16:01:04 -0400
X-Gm-Features: Ac12FXzOGGXGhE1duhbD0s56UlVQ0g2I8y9BFv08H051qzMmNgVQAGnFiVjL2Lc
Message-ID: <CAAkQn5JVPnN_dowQAjexom9O+2vThSOiNiY4woCgRPwGNNmt7w@mail.gmail.com>
Subject: Re: [PATCH 6/9] kunit: Enable direct registration of parameter arrays
 to a KUnit test
To: Dan Carpenter <dan.carpenter@linaro.org>
Cc: oe-kbuild@lists.linux.dev, rmoar@google.com, davidgow@google.com, 
	shuah@kernel.org, brendan.higgins@linux.dev, lkp@intel.com, 
	oe-kbuild-all@lists.linux.dev, elver@google.com, dvyukov@google.com, 
	lucas.demarchi@intel.com, thomas.hellstrom@linux.intel.com, 
	rodrigo.vivi@intel.com, linux-kselftest@vger.kernel.org, 
	kunit-dev@googlegroups.com, kasan-dev@googlegroups.com, 
	intel-xe@lists.freedesktop.org, dri-devel@lists.freedesktop.org, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: marievic@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=1huudaXn;       spf=pass
 (google.com: domain of marievic@google.com designates 2a00:1450:4864:20::52a
 as permitted sender) smtp.mailfrom=marievic@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Marie Zhussupova <marievic@google.com>
Reply-To: Marie Zhussupova <marievic@google.com>
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

On Thu, Jul 31, 2025 at 11:58=E2=80=AFAM Dan Carpenter <dan.carpenter@linar=
o.org> wrote:
>
> Hi Marie,
>
> kernel test robot noticed the following build warnings:
>
> https://git-scm.com/docs/git-format-patch#_base_tree_information]
>
> url:    https://github.com/intel-lab-lkp/linux/commits/Marie-Zhussupova/k=
unit-Add-parent-kunit-for-parameterized-test-context/20250730-033818
> base:   https://git.kernel.org/pub/scm/linux/kernel/git/shuah/linux-kself=
test.git kunit
> patch link:    https://lore.kernel.org/r/20250729193647.3410634-7-marievi=
c%40google.com
> patch subject: [PATCH 6/9] kunit: Enable direct registration of parameter=
 arrays to a KUnit test
> config: nios2-randconfig-r072-20250731 (https://download.01.org/0day-ci/a=
rchive/20250731/202507310854.pZvIcswn-lkp@intel.com/config)
> compiler: nios2-linux-gcc (GCC) 8.5.0
>
> If you fix the issue in a separate patch/commit (i.e. not just a new vers=
ion of
> the same patch/commit), kindly add following tags
> | Reported-by: kernel test robot <lkp@intel.com>
> | Reported-by: Dan Carpenter <dan.carpenter@linaro.org>
> | Closes: https://lore.kernel.org/r/202507310854.pZvIcswn-lkp@intel.com/
>
> New smatch warnings:
> lib/kunit/test.c:723 kunit_run_tests() error: we previously assumed 'test=
_case->generate_params' could be null (see line 714)
>
> vim +723 lib/kunit/test.c
>
> 914cc63eea6fbe Brendan Higgins     2019-09-23  681  int kunit_run_tests(s=
truct kunit_suite *suite)
> 914cc63eea6fbe Brendan Higgins     2019-09-23  682  {
> fadb08e7c7501e Arpitha Raghunandan 2020-11-16  683      char param_desc[K=
UNIT_PARAM_DESC_SIZE];
> 914cc63eea6fbe Brendan Higgins     2019-09-23  684      struct kunit_case=
 *test_case;
> acd8e8407b8fcc David Gow           2021-08-03  685      struct kunit_resu=
lt_stats suite_stats =3D { 0 };
> acd8e8407b8fcc David Gow           2021-08-03  686      struct kunit_resu=
lt_stats total_stats =3D { 0 };
> 8631cd2cf5fbf2 Marie Zhussupova    2025-07-29  687      const void *curr_=
param;
> 914cc63eea6fbe Brendan Higgins     2019-09-23  688
> c272612cb4a2f7 David Gow           2022-07-01  689      /* Taint the kern=
el so we know we've run tests. */
> c272612cb4a2f7 David Gow           2022-07-01  690      add_taint(TAINT_T=
EST, LOCKDEP_STILL_OK);
> c272612cb4a2f7 David Gow           2022-07-01  691
> 1cdba21db2ca31 Daniel Latypov      2022-04-29  692      if (suite->suite_=
init) {
> 1cdba21db2ca31 Daniel Latypov      2022-04-29  693              suite->su=
ite_init_err =3D suite->suite_init(suite);
> 1cdba21db2ca31 Daniel Latypov      2022-04-29  694              if (suite=
->suite_init_err) {
> 1cdba21db2ca31 Daniel Latypov      2022-04-29  695                      k=
unit_err(suite, KUNIT_SUBTEST_INDENT
> 1cdba21db2ca31 Daniel Latypov      2022-04-29  696                       =
         "# failed to initialize (%d)", suite->suite_init_err);
> 1cdba21db2ca31 Daniel Latypov      2022-04-29  697                      g=
oto suite_end;
> 1cdba21db2ca31 Daniel Latypov      2022-04-29  698              }
> 1cdba21db2ca31 Daniel Latypov      2022-04-29  699      }
> 1cdba21db2ca31 Daniel Latypov      2022-04-29  700
> cae56e1740f559 Daniel Latypov      2022-04-29  701      kunit_print_suite=
_start(suite);
> 914cc63eea6fbe Brendan Higgins     2019-09-23  702
> fadb08e7c7501e Arpitha Raghunandan 2020-11-16  703      kunit_suite_for_e=
ach_test_case(suite, test_case) {
> fadb08e7c7501e Arpitha Raghunandan 2020-11-16  704              struct ku=
nit test =3D { .param_value =3D NULL, .param_index =3D 0 };
> acd8e8407b8fcc David Gow           2021-08-03  705              struct ku=
nit_result_stats param_stats =3D { 0 };
> fadb08e7c7501e Arpitha Raghunandan 2020-11-16  706
> 887d85a0736ff3 Rae Moar            2023-03-08  707              kunit_ini=
t_test(&test, test_case->name, test_case->log);
> 03806177fa4cbb Marie Zhussupova    2025-07-29  708              __kunit_i=
nit_parent_test(test_case, &test);
> 03806177fa4cbb Marie Zhussupova    2025-07-29  709
> 529534e8cba3e6 Rae Moar            2023-07-25  710              if (test_=
case->status =3D=3D KUNIT_SKIPPED) {
> 529534e8cba3e6 Rae Moar            2023-07-25  711                      /=
* Test marked as skip */
> 529534e8cba3e6 Rae Moar            2023-07-25  712                      t=
est.status =3D KUNIT_SKIPPED;
> 529534e8cba3e6 Rae Moar            2023-07-25  713                      k=
unit_update_stats(&param_stats, test.status);
> 44c50ed8e59936 Marie Zhussupova    2025-07-29 @714              } else if=
 (!test_case->generate_params && !test.params_data.params) {
>                                                                          =
   ^^^^^^^^^^^^^^^^^^^^^^^^^^
> Imagine ->generate_parms is NULL but test.params_data.params is
> non-NULL.
>
> 37dbb4c7c7442d David Gow           2021-11-02  715                      /=
* Non-parameterised test. */
> 529534e8cba3e6 Rae Moar            2023-07-25  716                      t=
est_case->status =3D KUNIT_SKIPPED;
> 37dbb4c7c7442d David Gow           2021-11-02  717                      k=
unit_run_case_catch_errors(suite, test_case, &test);
> 37dbb4c7c7442d David Gow           2021-11-02  718                      k=
unit_update_stats(&param_stats, test.status);
> 03806177fa4cbb Marie Zhussupova    2025-07-29  719              } else if=
 (test_case->status !=3D KUNIT_FAILURE) {
> fadb08e7c7501e Arpitha Raghunandan 2020-11-16  720                      /=
* Get initial param. */
> fadb08e7c7501e Arpitha Raghunandan 2020-11-16  721                      p=
aram_desc[0] =3D '\0';
> 8631cd2cf5fbf2 Marie Zhussupova    2025-07-29  722                      /=
* TODO: Make generate_params try-catch */
> 13ee0c64bd88a3 Marie Zhussupova    2025-07-29 @723                      c=
urr_param =3D test_case->generate_params(&test, NULL, param_desc);
>                                                                          =
            ^^^^^^^^^^^^^^^^^^^^^^^^^^
> Then this could crash.
>
> I suspect that this is fine, but I bet that in the previous
> condition, just testing one would probably have been sufficient
> or maybe we could have change && to ||.

Hello Dan,

My apologies for the HTML version of this email earlier. Here is the
plain text version.

As of now, test.params_data.params can only be populated in a param_init
function, which can only be used if we register the test case with a
KUNIT_CASE_PARAM_WITH_INIT macro. That macro auto populates
test_case->generate_params with a function called
kunit_get_next_param_and_desc()
(which iterates over the parameter array) if the test user didn't provide t=
heir
own generator function. So, there shouldn't be a case where
test_case->generate_params is NULL but test.params_data.params is NON-NULL.

However, to be robust, we could add a NULL check  before calling
test_case->generate_params on line 723.

Thank you!
-Marie

>
> 529534e8cba3e6 Rae Moar            2023-07-25  724                      t=
est_case->status =3D KUNIT_SKIPPED;
> 6c738b52316c58 Rae Moar            2022-11-23  725                      k=
unit_log(KERN_INFO, &test, KUNIT_SUBTEST_INDENT KUNIT_SUBTEST_INDENT
> 6c738b52316c58 Rae Moar            2022-11-23  726                       =
         "KTAP version 1\n");
> 44b7da5fcd4c99 David Gow           2021-11-02  727                      k=
unit_log(KERN_INFO, &test, KUNIT_SUBTEST_INDENT KUNIT_SUBTEST_INDENT
> 44b7da5fcd4c99 David Gow           2021-11-02  728                       =
         "# Subtest: %s", test_case->name);
> fadb08e7c7501e Arpitha Raghunandan 2020-11-16  729
> 8631cd2cf5fbf2 Marie Zhussupova    2025-07-29  730                      w=
hile (curr_param) {
>
> --
> 0-DAY CI Kernel Test Service
> https://github.com/intel/lkp-tests/wiki
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AAkQn5JVPnN_dowQAjexom9O%2B2vThSOiNiY4woCgRPwGNNmt7w%40mail.gmail.com.
